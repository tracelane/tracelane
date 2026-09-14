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
use tracelane_shared::TenantId;
use tracing::instrument;
use uuid::Uuid;

use super::AppState;
use super::buffered::buffer_provider_stream;
use super::dispatch::{
    BENCH_MOCK_PROVIDER_ID, ProviderKey, breaker_outcome, dispatch_with_retry,
    provider_name_from_model, resolve_provider_key,
};
use super::errors::{provider_error_response, unroutable_model_response};
use super::spans::{
    CapturedInput, GatewayTiming, RequestConfig, SpanUsageMeta, build_gateway_span,
    spawn_span_publish,
};
use super::stream::{StreamContext, provider_stream_to_sse};

/// Does the request ask for SSE? Read from the raw body because the cache
/// decision happens before the typed request is re-serialised anywhere.
fn is_streaming_request(body: &serde_json::Value) -> bool {
    body.get("stream").and_then(serde_json::Value::as_bool) == Some(true)
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
#[instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
pub(crate) async fn chat_completions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    use crate::admission::{Chat, Route as _};
    // --- Step 1: ADMISSION. Nothing above this line resolves a credential. ---
    // Every refusal (401 / 403 / 400 / 429 / 402 / 503) is rendered on this wire
    // by `Chat::refuse`; an `Err` here means NO ledger row landed.
    let admitted = match crate::admission::admit::<Chat>(&state, &headers, body).await {
        Ok(a) => a,
        Err(refusal) => return Chat::refuse(refusal),
    };
    let crate::admission::Admitted {
        claims,
        identity,
        request_start,
        trace_id,
        inbound_parent,
        parsed,
        entitlements,
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
    let content_capture = super::config::content_capture_enabled(tenant_id);
    let online_eval_pending = match crate::online_eval::admission(
        tenant_id,
        trace_id,
        entitlements.as_deref(),
        content_capture,
    )
    .await
    {
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
    let provider_id = if bench_mock {
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
    // A4: BYOK lookup first — per-tenant ciphertext in `provider_keys` decrypted
    // with AAD bound to (tenant_id, provider_id). On miss (no row, decrypt fail,
    // pool unavailable) fall back to the legacy env var. The env var is derived
    // from THIS provider_id, so a miss yields an empty key (upstream 401), never
    // another provider's key.
    // The bench mock never dispatches upstream, so there is no credential
    // to resolve. Skipping the lookup also keeps the benchmark honest — it must
    // not measure a Postgres round-trip the mocked request would never make.
    let provider_key = if bench_mock {
        std::sync::Arc::new(secrecy::SecretString::from(String::new()))
    } else {
        let key_env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id);
        // First-value path: a launch-day user who has not added BYOK yet must be told
        // to ADD a key, not that their key was "rejected". Dispatching an empty
        // credential and relaying the upstream 401 read as "my key is broken" for a
        // user who had no key at all. Fail here, before the upstream round-trip.
        match resolve_provider_key(tenant_id, provider_id, key_env).await {
            ProviderKey::Found(k) => k,
            outcome => {
                let (status, code, message) = match outcome {
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
                    _ => (
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
    let cache_key = state
        .semantic_cache
        .as_ref()
        .map(|_| crate::semantic_cache::request_key(&chat_request));

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
    {
        let rag_context = crate::guardrail::context::extract_rag_context(&body);
        let session = crate::guardrail::SessionState::fresh(identity.conversation_id.clone());
        let gr = state
            .guardrail
            .evaluate_request(crate::guardrail::RequestInputs {
                tenant_id,
                api_key_id: Some(claims.sub.as_str()),
                correlation_id,
                request: &chat_request,
                rag_context,
                session,
                actor: claims.sub.as_str(),
            })
            .await;
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
        if gr.outcome.decision == crate::guardrail::Decision::Redact {
            guardrail_redaction_map =
                crate::guardrail::streaming::redact_request_in_place(&mut chat_request);
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
    // ADR-036: per-(provider, region) circuit breaker. Region is "default" —
    // ChatRequest carries no region tag at this layer (Bedrock's region is
    // adapter-internal). If the breaker is Open we fail fast with 503 +
    // Retry-After rather than tying up a worker slot on a known-bad upstream.
    let upstream = provider_name_from_model(&model);
    let region = "default";
    // ADR-038 kill.upstream.<provider> force-opens the breaker (operator
    // disable / provider incident), in addition to the breaker's own state.
    let upstream_killed = state.kill_switch.upstream_killed(upstream);
    if upstream_killed || !state.circuit_breaker.allow(upstream, region) {
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

    // Latency-split boundary: everything before this mark is gateway overhead
    // (auth, quota, predictive, guardrail engine + the Step-4 audit append,
    // untrusted-wrap); everything after, up to provider-complete, is the provider
    // round-trip (incl. A7 retry / cross-provider failover). Stamped once, here.
    let dispatch_ts = chrono::Utc::now();
    // B-375 (b): `dispatch_guard` has been ARMED since admission published the
    // ledger row. From here until a span is recorded by one of the normal paths
    // the request is "in flight with the provider" and a client that hangs up
    // drops this handler future — which recorded NOTHING before the guard
    // existed (the prod proof for B-375 found it: a cancel at 1.5 s against a
    // 1.25 s time-to-first-chunk landed no span at all). Disarmed at every site
    // that records its own span; if it is still armed when the future is
    // dropped, `Drop` records a `client_cancelled` error span.
    timer.mark("guardrails");
    // Emit against the SAME interval the span's overhead number opens with —
    // `dispatch_ts - request_start` — so the log line and the span agree by
    // construction instead of by two similar-looking clocks.
    timer.emit_if_slow(
        &state.hotpath,
        u64::try_from(
            (dispatch_ts - request_start)
                .num_microseconds()
                .unwrap_or(0),
        )
        .unwrap_or(0),
    );
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
        if let Some(captured) = CapturedInput::build(tenant_id, &chat_request) {
            captured.apply(&mut span.attributes);
        }
        // GWY-48, span site 1 of 4. A cache hit ran under the configuration the
        // CALLER sent on THIS request, not the one that produced the stored
        // answer — recording the caller's own settings is what makes "why did I
        // get this" answerable on a hit at all.
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
        return (
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
            .into_response();
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
        dispatch_with_retry(
            &state.providers,
            &chat_request,
            provider_key.expose_secret(),
            &model,
            tenant_id,
            crate::providers::failover::retry_policy(state.failover),
        )
        .await
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
        state.circuit_breaker.record(upstream, region, ok);
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
    let cross_provider_failover = headers
        .get("x-tracelane-failover")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-provider"));
    // `Some(primary_provider)` once a cross-provider failover actually served the
    // request — threaded onto the span so the Gateway-ops rollup can count it and
    // name the primary that errored.
    let mut failover_from: Option<&'static str> = None;
    if provider_result.is_err() && cross_provider_failover {
        let primary_family = provider_name_from_model(&model);
        for (fo_provider, fo_model) in
            crate::providers::failover::cross_provider_candidates(primary_family, state.failover)
        {
            if state.kill_switch.upstream_killed(fo_provider)
                || !state.circuit_breaker.allow(fo_provider, region)
            {
                continue;
            }
            // Fail closed on an unroutable failover candidate — skip it,
            // never default to a provider (its key would be the wrong one).
            let Some(fo_pid) = crate::providers::ProviderRegistry::provider_id_for_model(fo_model)
            else {
                continue;
            };
            let fo_env = crate::providers::ProviderRegistry::env_var_for_provider_id(fo_pid);
            // Failover keeps its skip-on-unresolvable behaviour: a provider we
            // cannot key for is simply not a failover candidate.
            let fo_key = match resolve_provider_key(tenant_id, fo_pid, fo_env).await {
                ProviderKey::Found(k) => k,
                _ => std::sync::Arc::new(secrecy::SecretString::from(String::new())),
            };
            if fo_key.expose_secret().is_empty() {
                tracing::debug!(
                    provider = fo_provider,
                    "cross-provider failover skipped — no BYOK key for this provider"
                );
                continue;
            }
            let mut fo_request = chat_request.clone();
            fo_request.model = fo_model.to_string();
            let fo_result = dispatch_with_retry(
                &state.providers,
                &fo_request,
                fo_key.expose_secret(),
                fo_model,
                tenant_id,
                crate::providers::failover::retry_policy(state.failover),
            )
            .await;
            if let Some(ok) = breaker_outcome(&fo_result) {
                state.circuit_breaker.record(fo_provider, region, ok);
            }
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
                provider_result = fo_result;
                break;
            }
        }
    }

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
            let err_reason = if http
                .is_some_and(crate::providers::ProviderHttpError::is_auth_rejection)
            {
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
            dispatch_guard.abort(err_reason, None);

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
                return provider_error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "provider_rate_limited",
                    Some(
                        "the upstream provider rate-limited or quota-exhausted this request — retry later, or check the provider account's plan and billing",
                    ),
                    Some(upstream),
                    Some("60"),
                );
            }

            // An upstream 404 means the model does not exist for this
            // account — the caller must change the model string, not retry. As a
            // 502 it read as a Tracelane outage. Observed live: AI Studio 404s
            // gemini-2.5-flash as "no longer available to new users".
            if http.is_some_and(crate::providers::ProviderHttpError::is_model_not_found) {
                tracing::warn!(provider = upstream, "upstream reports model not found");
                return provider_error_response(
                    StatusCode::NOT_FOUND,
                    "model_not_found",
                    Some(
                        "the upstream provider does not recognise this model for this account — check the model name and that your provider account has access to it",
                    ),
                    Some(upstream),
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
                return provider_error_response(
                    // Mirror the upstream status so the caller sees exactly what the
                    // provider said. 401/403/404/429 are claimed by the branches
                    // above and can never reach here; anything unrepresentable
                    // degrades to 400 (still client-class, never 5xx).
                    StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST),
                    "provider_request_rejected",
                    Some(&message),
                    Some(upstream),
                    None,
                );
            }

            tracing::error!(error = %err, "provider dispatch failed after retry");
            return provider_error_response(
                StatusCode::BAD_GATEWAY,
                "provider unavailable",
                None,
                None,
                None,
            );
        }
    };

    // --- Step 6: Response ---
    let is_streaming = body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if is_streaming {
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
            tenant_id: tenant_id.clone(),
            api_key_id: Some(claims.sub.clone()),
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
            },
        );
        Sse::new(sse).into_response()
    } else {
        let response_inputs = crate::guardrail::ResponseInputs {
            tenant_id: tenant_id.clone(),
            api_key_id: Some(claims.sub.clone()),
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
            claims.api_key_id(),
            state.semantic_cache.clone(),
            cache_key,
            CapturedInput::build(tenant_id, &chat_request),
            // GWY-48, span site 2 of 4.
            request_config,
            online_eval_pending,
        )
        .await;
        // The buffered path recorded its span (success or error) inside
        // `buffer_provider_stream`; a client that hung up DURING that await
        // dropped this future above this line, and the guard's `Drop` recorded
        // the cancellation instead.
        dispatch_guard.disarm();
        resp.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const UUID_AB: &str = "00000000-0000-0000-0000-0000000000ab";

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
    /// another's `before` read and its assertion (`tl-ci-1`'s first run,
    /// 2026-09-12: `a_request_that_completes…` read 1 where it expected 0).
    /// One lock, held for the whole test.
    static CANCEL_COUNTER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    use super::super::dispatch::REQUESTS_CANCELLED_IN_DISPATCH;
    use crate::handler_harness::{
        LoopbackBypassGuard, authed, body_json, registry_pointing_ollama_at, test_state,
    };

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
}
