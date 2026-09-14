//! `POST /v1/embeddings` — GWY-26 (B-385 §2d split of `server.rs`).

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use secrecy::ExposeSecret as _;
use tracelane_shared::{TenantId, TracelaneSpan};
use tracing::instrument;
use uuid::Uuid;

use super::AppState;
use super::dispatch::{
    DispatchGuard, ProviderKey, breaker_outcome, provider_name_from_model, resolve_provider_key,
};
use super::errors::{
    classify_dispatch_error, dispatch_failure_response, provider_error_response,
    unroutable_model_response,
};
use super::spans::{
    CallerIdentity, GatewayTiming, SpanUsageMeta, build_gateway_span, spawn_span_publish,
};

/// Embeddings span. Same shape as the chat span (one definition of the
/// attribute set) with the OTel GenAI `embeddings` operation name, so an
/// embeddings call is a first-class row in `/traces` rather than a chat call
/// that happens to have zero output tokens.
#[allow(clippy::too_many_arguments)]
fn build_embeddings_span(
    tenant_id: &TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    model: &str,
    identity: &CallerIdentity,
    start_time: chrono::DateTime<chrono::Utc>,
    input_tokens: u32,
    timing: Option<GatewayTiming>,
    error_reason: Option<&str>,
    api_key_id: Option<&str>,
) -> TracelaneSpan {
    let mut span = build_gateway_span(
        tenant_id,
        trace_id,
        parent_span_id,
        model,
        identity,
        start_time,
        input_tokens,
        // Embeddings produce no completion tokens. Reporting anything else
        // would inflate every token rollup that sums output tokens.
        0,
        None,
        SpanUsageMeta::default(),
        None,
        timing,
        error_reason,
        api_key_id,
    );
    span.name = "gen_ai.embeddings".to_string();
    span.attributes.gen_ai_operation_name = Some("embeddings".to_string());
    span
}

/// Embeddings handler — `POST /v1/embeddings` (GWY-26).
///
/// The OpenAI Embeddings shape, so an existing client works by swapping its
/// base URL. It exists because a RAG agent's retrieval step was invisible to
/// the flight recorder: `/v1/chat/completions` was the gateway's only inference
/// route, so every embeddings call went straight to the provider — no span, no
/// ledger entry, no quota, no BYOK.
///
/// ## Pipeline — the ORDER is the security property
///
/// ```text
/// ADMISSION (crate::admission — auth → scope → parse → entitlements + rate limit
///   → monthly quota → key + workspace budgets → predictive → audit publish)
/// → route (fail-CLOSED) → BYOK key → breaker → dispatch → span + meter
/// ```
///
/// B-385: the admission half is the SAME typed pipeline the chat and Anthropic
/// routes run, so the three cannot diverge again. Nothing that resolves a
/// credential or touches an upstream sits above the auth step, so an
/// unauthenticated request cannot reach any of it. Asserted by
/// `embeddings_without_authorization_is_rejected`, not by this comment
/// (`crates/gateway/CLAUDE.md`: "adding a route without replicating that
/// sequence ships an unauthenticated endpoint").
///
/// ## What it deliberately does NOT run, and why
///
/// - **Inline guardrails.** The rails are defined over a `ChatRequest` —
///   messages, tool definitions, tool results. An embeddings payload has none
///   of those. Synthesising a fake `ChatRequest` to make the rails fire would
///   write a verdict about a request that was never made into a tamper-evident
///   ledger, which is worse than no verdict. R2 (secrets/PII) genuinely applies
///   to embedding input and needs a rail that accepts raw text; that is a rail
///   change, not a handler change. (The PREDICTIVE layer does run, inside the
///   shared pipeline, over the raw body: every predictor keys on a field —
///   `messages`, `tools`, `tool_name`, `protocol`, … — that an embeddings body
///   never carries, so it answers `Allow` at its first lookup and records
///   nothing. Running it costs eleven map probes and keeps the pipeline ONE.)
/// - **Untrusted-data wrapping.** Sentinel-wrapping exists so a downstream LLM
///   cannot be steered by tool output. Nothing downstream of an embedding
///   vector interprets instructions.
/// - **Streaming / cross-provider failover / prompt promotion.** The embeddings
///   API is not streamed, and there is no cross-provider embedding equivalence
///   to fail over to — vectors from two providers are not interchangeable.
///
/// ## Fail directions
///
/// Fail-CLOSED: auth, audit publish (`503 audit_unavailable`), model routing
/// (`400 unroutable_model`), provider-key resolution, input validation.
/// Fail-OPEN: span publish and byte metering are off the response path — a
/// NATS or ClickHouse problem never fails a request that the provider served.
#[instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
pub(crate) async fn embeddings_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    use crate::admission::{Embeddings, Route as _};
    // --- Step 1: ADMISSION. Nothing above this line resolves a credential. ---
    // The SAME pipeline as chat (`crate::admission`): auth → scope → parse →
    // entitlements + rate limit → monthly quota (the same tracker as chat: one
    // allowance) → key + workspace budgets → predictive → audit publish
    // (fail-CLOSED). The parse sits ABOVE the quota by construction, so a
    // malformed request never consumes a trace from the paid allowance.
    let admitted = match crate::admission::admit::<Embeddings>(&state, &headers, body).await {
        Ok(a) => a,
        Err(refusal) => return Embeddings::refuse(refusal),
    };
    let crate::admission::Admitted {
        claims,
        identity,
        request_start,
        trace_id,
        inbound_parent,
        parsed,
        mut dispatch_guard,
        ..
    } = admitted;
    let request = parsed.request;
    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());
    // The caller's model string — kept verbatim through routing, the span and
    // the ledger even when a `tracelane.yaml` alias rewrites what goes upstream.
    let model = request.model.clone();

    // Every exit below this line has a ledger row behind it (R13). The armed
    // `dispatch_guard` records a `client_cancelled` span if the handler future
    // is dropped; each refusal records its OWN embeddings-shaped error span and
    // disarms, so a refused request is visible in /traces rather than silent.
    let refuse_with_span = |dispatch_guard: &mut DispatchGuard, state: &AppState, code: &str| {
        spawn_span_publish(
            state,
            build_embeddings_span(
                tenant_id,
                trace_id,
                inbound_parent,
                &model,
                &identity,
                request_start,
                0,
                None,
                Some(code),
                claims.api_key_id(),
            ),
        );
        dispatch_guard.disarm();
    };

    // --- Step 2: Route. Fail-CLOSED — no default provider. ---
    let Some(provider_id) = crate::providers::ProviderRegistry::provider_id_for_model(&model)
    else {
        refuse_with_span(&mut dispatch_guard, &state, "unroutable_model");
        return unroutable_model_response(&model);
    };
    // Only providers speaking the OpenAI embeddings wire format can serve this.
    // Refuse by name rather than forward a shape the provider cannot parse and
    // relay its 400 as if it were ours.
    let Some(adapter) = state.providers.openai_compatible(provider_id) else {
        tracing::warn!(
            provider = provider_id,
            "embeddings requested for a provider with no OpenAI-compatible embeddings endpoint"
        );
        refuse_with_span(
            &mut dispatch_guard,
            &state,
            "embeddings_unsupported_provider",
        );
        return provider_error_response(
            StatusCode::BAD_REQUEST,
            "embeddings_unsupported_provider",
            Some(
                "this provider does not expose an OpenAI-compatible /v1/embeddings endpoint — \
                 use an OpenAI or OpenAI-compatible embedding model, or map one in tracelane.yaml",
            ),
            Some(provider_id),
            None,
        );
    };

    // --- Step 3: BYOK key. Fail-CLOSED, and the two failures need OPPOSITE
    // user actions (add a key vs rotate one) — never collapsed into one. ---
    let key_env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id);
    let provider_key = match resolve_provider_key(tenant_id, provider_id, key_env).await {
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
            refuse_with_span(&mut dispatch_guard, &state, code);
            return provider_error_response(status, code, Some(message), Some(provider_id), None);
        }
    };

    // --- Step 4: Breaker + kill switch (ADR-036/038) ---
    let upstream = provider_name_from_model(&model);
    let region = "default";
    let upstream_killed = state.kill_switch.upstream_killed(upstream);
    if upstream_killed || !state.circuit_breaker.allow(upstream, region) {
        tracing::warn!(
            provider = upstream,
            killed = upstream_killed,
            "upstream unavailable (circuit open or killed) — short-circuiting with 503"
        );
        refuse_with_span(
            &mut dispatch_guard,
            &state,
            if upstream_killed {
                "upstream_killed"
            } else {
                "upstream_circuit_open"
            },
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

    // --- Step 5: Dispatch ---
    // GWY-39: the alias's upstream model is what the provider is asked for; the
    // caller's alias stays on `model` for the span, the ledger and the echoed
    // response.
    let mut upstream_request = request;
    if let Some(a) = super::config::alias(&model) {
        upstream_request.model.clone_from(&a.upstream_model);
    }
    let dispatch_ts = chrono::Utc::now();
    let result = adapter
        .embeddings(&upstream_request, provider_key.expose_secret(), tenant_id)
        .await;
    // The provider answered (or failed): every path below records its own span.
    dispatch_guard.disarm();
    let provider_complete_ts = chrono::Utc::now();
    if let Some(ok) = breaker_outcome(&result) {
        state.circuit_breaker.record(upstream, region, ok);
    }

    let mut response = match result {
        Ok(r) => r,
        Err(err) => {
            let failure = classify_dispatch_error(&err);
            let status_code = err
                .downcast_ref::<crate::providers::ProviderHttpError>()
                .map(|e| e.status);
            crate::otlp_emit::emit_operation_exception(
                tenant_id,
                upstream,
                region,
                "dispatch_failed",
                status_code,
            );
            //  #3: a failure MUST be countable (status_code = 2), or the
            // error-rate metric is structurally pinned at 0% for this route.
            spawn_span_publish(
                &state,
                build_embeddings_span(
                    tenant_id,
                    trace_id,
                    inbound_parent,
                    &model,
                    &identity,
                    request_start,
                    0,
                    None,
                    Some(failure.reason()),
                    claims.api_key_id(),
                ),
            );
            tracing::warn!(
                provider = upstream,
                reason = failure.reason(),
                status = ?status_code,
                "embeddings dispatch failed"
            );
            return dispatch_failure_response(failure, upstream);
        }
    };

    // --- Step 6: Record, meter, respond ---
    let billable = response.billable_tokens();
    spawn_span_publish(
        &state,
        build_embeddings_span(
            tenant_id,
            trace_id,
            inbound_parent,
            &model,
            &identity,
            request_start,
            billable,
            Some(GatewayTiming {
                dispatch_ts,
                provider_complete_ts,
                // Embeddings are a single non-streamed round-trip: there is no
                // first chunk distinct from the response.
                ttft_us: None,
            }),
            None,
            claims.api_key_id(),
        ),
    );

    // Echo the model the CALLER asked for. A `tracelane.yaml` alias is the
    // caller's own vocabulary; handing back the upstream name would break a
    // client that round-trips `response.model` into its next request.
    response.model = model;
    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(all(test, debug_assertions))]
mod route_tests {
    use super::*;
    use crate::providers::ProviderRegistry;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // B-385 (2c): the harness lives in `crate::handler_harness` — `test_state`,
    // `authed`, `body_json`, `registry_pointing_ollama_at`, the loopback guard.
    use crate::handler_harness::{
        LoopbackBypassGuard, authed, body_json, registry_pointing_ollama_at, test_state,
    };

    const VECTORS: [f32; 4] = [0.1, 0.2, 0.3, 0.4];

    async fn embeddings_mock() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list",
                "data": [{ "object": "embedding", "index": 0, "embedding": VECTORS }],
                "model": "nomic-embed-text",
                "usage": { "prompt_tokens": 11, "total_tokens": 11 }
            })))
            .mount(&server)
            .await;
        server
    }

    // ── Negative first: every way in that must be REFUSED. ──

    #[tokio::test]
    async fn embeddings_without_authorization_is_rejected() {
        // The failure this guards is the one crates/gateway/CLAUDE.md names:
        // "adding a route without replicating that sequence ships an
        // unauthenticated endpoint". There is no Tower auth layer to inherit.
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let resp = embeddings_handler(
            State(state),
            HeaderMap::new(),
            Json(json!({ "model": "text-embedding-3-small", "input": "hi" })),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an unauthenticated embeddings request must never reach routing or a credential"
        );
    }

    #[tokio::test]
    async fn embeddings_rejects_an_unroutable_model_rather_than_defaulting() {
        // No default provider. Defaulting here would ship one provider's
        // BYOK key to a model the caller never named.
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": "no-such-model-family", "input": "hi" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await["error"], "unroutable_model");
    }

    #[tokio::test]
    async fn embeddings_rejects_a_provider_with_no_openai_shaped_endpoint() {
        // Anthropic has no OpenAI-compatible /v1/embeddings. Forwarding the
        // request on a guess would return an upstream 400 that reads as ours.
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": "claude-sonnet-4-6", "input": "hi" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "embeddings_unsupported_provider");
        assert_eq!(body["provider"], "anthropic");
    }

    #[tokio::test]
    async fn embeddings_rejects_a_body_with_no_input() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        for bad in [
            json!({ "model": "text-embedding-3-small" }),
            json!({ "model": "text-embedding-3-small", "input": [] }),
            json!({ "input": "orphan input, no model" }),
        ] {
            let resp = embeddings_handler(State(state.clone()), authed(), Json(bad.clone())).await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{bad} must be refused before a credential is resolved"
            );
        }
    }

    #[tokio::test]
    async fn embeddings_maps_an_upstream_401_to_a_key_rejection_not_an_outage() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(401).set_body_string("bad key sk-leaked-value"))
            .mount(&server)
            .await;

        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": "ollama/nomic-embed-text", "input": "hi" })),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an upstream 401 is the tenant's key being rejected, not a 502 outage"
        );
        let body = body_json(resp).await;
        assert_eq!(body["error"], "provider_key_rejected");
        assert!(
            !body.to_string().contains("sk-leaked-value"),
            "the upstream body must never cross this boundary: {body}"
        );
    }

    // ── The end state: a caller gets usable vectors back. ──

    #[tokio::test]
    async fn embeddings_returns_vectors_a_caller_can_use() {
        let _bypass = LoopbackBypassGuard::new();
        let server = embeddings_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));

        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": "ollama/nomic-embed-text", "input": "embed me" })),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        // Not "it returned 200": the actual vector the caller came for.
        let embedding = body["data"][0]["embedding"]
            .as_array()
            .expect("data[0].embedding must be an array of floats");
        let got: Vec<f64> = embedding
            .iter()
            .map(|v| v.as_f64().expect("float"))
            .collect();
        assert_eq!(got.len(), 4);
        for (i, want) in VECTORS.iter().enumerate() {
            assert!(
                (got[i] - f64::from(*want)).abs() < 1e-6,
                "embedding[{i}] = {} , want {want}",
                got[i]
            );
        }
        assert_eq!(body["object"], "list");
        assert_eq!(body["usage"]["prompt_tokens"], 11);
        // The model the caller sent is echoed back, so a client that
        // round-trips `response.model` keeps working.
        assert_eq!(body["model"], "ollama/nomic-embed-text");
    }

    #[test]
    fn openai_bare_embedding_models_route_to_openai() {
        // Without this arm `text-embedding-3-small` — the most-used embedding
        // model there is — fail-closed as `unroutable_model`, because it
        // carries no gpt/o1/o3 prefix.
        assert_eq!(
            ProviderRegistry::provider_id_for_model("text-embedding-3-small"),
            Some("openai")
        );
        assert_eq!(
            ProviderRegistry::provider_id_for_model("text-embedding-ada-002"),
            Some("openai")
        );
        // Still fail-closed on a name nothing serves.
        assert_eq!(
            ProviderRegistry::provider_id_for_model("text-embedding"),
            None,
            "the arm must not swallow a bare prefix with no model after it"
        );
    }

    /// INCLUDE_STR GUARD (B-385 2c) — a ROUTE-MOUNT LITERAL in `run()`, kept.
    #[test]
    fn the_embeddings_route_is_mounted_unconditionally() {
        // Ten of the gateway's route groups are env-conditional. This one must
        // not be: an embeddings call that 404s is the same silent bypass GWY-26
        // exists to close. Scan only the non-test prefix so this literal does
        // not match itself (same technique as the bench-gate guard above).
        let full = include_str!("../server.rs");
        let non_test = &full[..full.find("#[cfg(test)]").unwrap_or(full.len())];
        assert!(
            non_test.contains(concat!(
                r#".route("/v1/embeddings", "#,
                "post(embeddings_handler))"
            )),
            "the /v1/embeddings route must be mounted in the unconditional router"
        );
    }

    // ── GWY-39: `tracelane.yaml` makes an unroutable model routable. ──

    /// The whole GWY-39 claim in one test, because the config slot is
    /// process-global and write-once: a model the built-in prefix table cannot
    /// route becomes routable, reaches the aliased provider, and is sent
    /// upstream under the aliased upstream model name.
    #[tokio::test]
    async fn tracelane_yaml_alias_routes_a_model_the_prefix_table_cannot() {
        const ALIAS: &str = "tl-test-alias-embedder";

        // 1. FALSIFY FIRST: without the file this model is unroutable.
        assert_eq!(
            ProviderRegistry::provider_id_for_model(ALIAS),
            None,
            "precondition: the alias must be unroutable before the config is installed"
        );

        // 2. Install exactly the block apps/docs/providers.mdx describes.
        let cfg = crate::server::config::parse(&format!(
            "models:\n  {ALIAS}:\n    provider: ollama\n    model: nomic-embed-text\n"
        ))
        .expect("documented tracelane.yaml block must parse");
        assert!(
            crate::server::config::install_for_test(cfg),
            "this must be the only test that installs a config"
        );

        // 3. The canonical map now resolves it — and so does every delegate,
        //    because the alias lives INSIDE `provider_id_for_model`.
        assert_eq!(
            ProviderRegistry::provider_id_for_model(ALIAS),
            Some("ollama")
        );
        assert_eq!(provider_name_from_model(ALIAS), "ollama");
        assert_eq!(
            ProviderRegistry::provider_id_for_model(ALIAS)
                .map(ProviderRegistry::env_var_for_provider_id),
            Some(""),
            "the alias must resolve Ollama's (empty) credential, not another provider's"
        );
        // Exact match only — an alias must never widen into a prefix rule.
        assert_eq!(
            ProviderRegistry::provider_id_for_model(&format!("{ALIAS}-v2")),
            None
        );

        // 4. End to end: the request routes, and the UPSTREAM sees the aliased
        //    model name while the CALLER gets their own name back.
        let _bypass = LoopbackBypassGuard::new();
        let server = embeddings_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({ "model": ALIAS, "input": "embed me" })),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the alias must make a previously-400 model serve a real response"
        );
        let body = body_json(resp).await;
        assert_eq!(body["model"], ALIAS, "the caller's own name is echoed back");
        assert!(body["data"][0]["embedding"].is_array());

        // The discriminating field: what the provider was actually asked for.
        let received = server
            .received_requests()
            .await
            .expect("mock recorded requests");
        let sent: serde_json::Value =
            serde_json::from_slice(&received[0].body).expect("upstream body is JSON");
        assert_eq!(
            sent["model"], "nomic-embed-text",
            "the upstream must be asked for the aliased model, not the alias"
        );
    }
}
