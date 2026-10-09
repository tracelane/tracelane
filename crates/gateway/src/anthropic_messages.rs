//! `GWY-47` — the Anthropic-native wire: `POST /v1/messages` (+ `/count_tokens`).
//!
//! ## Why this exists
//!
//! Claude Code, the Anthropic SDKs, Cursor's Anthropic path and LiteLLM's
//! `AIGatewayBench` all speak **Anthropic Messages**, not OpenAI chat/completions.
//! Before this route the only way to record those calls was to rewrite the client.
//! Now it is two environment variables (`ANTHROPIC_BASE_URL` + a `tlane_` key), and
//! every call lands as a gateway span and a tamper-evident ledger row.
//!
//! ## The two properties that fight each other, and how they are resolved
//!
//! 1. **Byte fidelity.** An SDK that parses `thinking` blocks, `tool_use` blocks,
//!    `cache_control`, and beta features must receive *exactly* what Anthropic sent.
//!    So the request forwards the caller's ORIGINAL body bytes and the response
//!    relays the provider's ORIGINAL SSE frames — this module never re-serialises a
//!    successful body.
//! 2. **Enforce-before-yield.** `guardrail::ResponseGuard` is the one response-side
//!    seam (R2/R6/R7 + the R1 output cap) and it works on *text*, holding back a
//!    512-char tail so a redaction lands before any prefix is emitted.
//!
//! **The resolution: hold back the RAW FRAMES, not the text.** Text deltas are fed
//! to the guard; a frame is released verbatim only once the guard has released text
//! covering it AND that released text is byte-identical to what the provider sent.
//! So in the default configuration — no rail redacting — the client receives the
//! provider's byte stream unchanged, merely delayed by the hold-back. If a rail
//! *does* redact, byte fidelity is deliberately given up for the remainder of the
//! stream (see [`Relay`]) and the guard's transformed text is synthesised into
//! `content_block_delta` frames instead. A block drops the held frames and ends the
//! stream with an Anthropic `error` event. **Byte fidelity is a property of the
//! clean path; it is not allowed to outrank the seam.**
//!
//! ## The pipeline — the ORDER is the security property
//!
//! ```text
//! auth (authorization OR x-api-key) → chat scope → parse → route (Anthropic only)
//! → entitlements + rate limit → monthly quota → per-key budget → workspace budget
//! → detection (OBSERVE-first) → audit publish (fail-CLOSED 503) → BYOK
//! → request guardrails (fail-CLOSED) → breaker/kill-switch → forward → relay
//! ```
//!
//! It mirrors `server::chat_completions_handler` step for step and **calls the same
//! functions** at every stage (`auth::validate_authorization`,
//! `state.rate_limiter`, `state.quota_tracker`, `spend::tracker()`,
//! `state.predictive`, `state.audit_chain.publish`, `server::resolve_provider_key`,
//! `state.guardrail`, `server::build_gateway_span`, `pricing::cost_usd`). It does
//! NOT call into the chat handler, and the chat handler does not call into it —
//! asserted by `chat_handler_gains_no_call_into_this_module`, because
//! `crates/gateway/CLAUDE.md` warns that "adding a route without replicating that
//! sequence ships an unauthenticated endpoint" and the cheapest way to break the
//! hot path is to refactor it for a second caller.
//!
//! ## What it deliberately does NOT do
//!
//! - **No failover, no same-provider retry.** An Anthropic wire has exactly one
//!   provider (spec `GWY-47` §6); re-dispatching to OpenAI would mean translating
//!   the body, which is the thing this route exists to avoid.
//! - **No semantic cache.** The cache key is derived from a `ChatRequest` and the
//!   cached body is OpenAI-shaped — replaying one here would hand an Anthropic SDK
//!   a body it cannot parse.
//! - **No online-eval sampling.** The judge needs a flattened question and the
//!   post-guardrail answer text; this relay is byte-oriented. A follow-up, not an
//!   omission by accident.
//! - **No bench-mock arm.** The benchmark drives `/v1/chat/completions`; adding a
//!   second bypass site is precisely what `.claude/rules/tenancy.md` forbids.

use crate::admission::Route as _;
use std::sync::OnceLock;

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use tracelane_policy::pii::RedactionEntry;
use tracelane_shared::{
    ChatRequest, ContentPart, Message, MessageContent, Role, TenantId, Tool, Usage,
};
use tracing::instrument;
use uuid::Uuid;

use crate::rate_limiter::RateLimitDecision;
use crate::server::{AppState, CapturedInput, GatewayTiming, ProviderKey, SpanUsageMeta};

/// The provider this route serves, and the only one it will ever serve.
const PROVIDER_ID: &str = "anthropic";

/// Anthropic's own default when the caller does not send `anthropic-version`.
/// Matched to `providers/anthropic.rs`, which pins the same value.
const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";

/// Upstream timeout, matched to `AnthropicProvider::new` so the two paths to the
/// same origin cannot disagree about how long a slow completion may take.
const UPSTREAM_TIMEOUT_SECS: u64 = 300;

// ── Anthropic error shape ────────────────────────────────────────────────────

/// Build an Anthropic-shaped error body.
///
/// The SDKs parse `{"type":"error","error":{"type":…,"message":…}}` and surface
/// anything else as "unknown error", which is how a perfectly clear 403 becomes an
/// unactionable failure inside Claude Code. `extra` carries our own machine-readable
/// fields (`code`, `correlation_id`, `provider`) — SDKs ignore unknown members, and
/// a support conversation starts from the correlation id.
///
/// # Errors
/// Infallible. The body is scrubbed with `tracelane_shared::redact::scrub` before it
/// leaves, defence in depth for the one thing that must never appear in an error:
/// a credential the caller pasted into a field we echo.
fn anthropic_error(
    status: StatusCode,
    error_type: &str,
    message: &str,
    extra: &[(&str, Value)],
) -> Response {
    let mut err = serde_json::Map::new();
    err.insert("type".into(), error_type.into());
    err.insert("message".into(), message.into());
    for (k, v) in extra {
        err.insert((*k).to_owned(), v.clone());
    }
    let body = json!({ "type": "error", "error": Value::Object(err) });
    let raw = serde_json::to_vec(&body).unwrap_or_else(|_| {
        br#"{"type":"error","error":{"type":"api_error","message":"internal"}}"#.to_vec()
    });
    let scrubbed = tracelane_shared::redact::scrub(&raw);
    let mut resp = (status, scrubbed).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp
}

/// The Anthropic error `type` string for an HTTP status, per their API reference.
/// One mapping so a status and its type can never disagree across call sites.
fn error_type_for(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "invalid_request_error",
        StatusCode::UNAUTHORIZED => "authentication_error",
        StatusCode::FORBIDDEN => "permission_error",
        StatusCode::NOT_FOUND => "not_found_error",
        StatusCode::PAYLOAD_TOO_LARGE => "request_too_large",
        StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
        StatusCode::SERVICE_UNAVAILABLE => "overloaded_error",
        _ => "api_error",
    }
}

/// `anthropic_error` with the type derived from the status and a `code` field for
/// machine consumers. The `code` vocabulary is deliberately the SAME token set the
/// OpenAI-shaped chat route returns (`unroutable_model`, `audit_unavailable`,
/// `provider_key_rejected`, …), so a customer running both wires greps one word.
fn coded_error(status: StatusCode, code: &str, message: &str) -> Response {
    crate::kms::retry_after(
        anthropic_error(
            status,
            error_type_for(status),
            message,
            &[("code", json!(code))],
        ),
        code,
    )
}

// ── Credential extraction ────────────────────────────────────────────────────

/// The `Authorization`-header value to validate, from either header this route
/// accepts.
///
/// **`x-api-key` is accepted on THESE TWO ROUTES ONLY**, because it is what an
/// Anthropic SDK sends when it is configured with `ANTHROPIC_API_KEY` — and a
/// customer who sets that variable instead of `ANTHROPIC_AUTH_TOKEN` would
/// otherwise get an unexplainable 401. `/v1/chat/completions`, `/v1/embeddings` and
/// every control-plane route still read `authorization` and nothing else;
/// `x_api_key_is_not_accepted_on_the_chat_route` asserts that rather than assuming
/// it.
///
/// The value is wrapped into `Bearer <token>` and handed to the SAME
/// `auth::validate_authorization` every other route uses — there is no second
/// validator, no second cache and no second scope resolution. A `Bearer ` prefix
/// already present in the header is not doubled.
fn authorization_value(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Some(v.to_owned());
    }
    let raw = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())?;
    Some(format!(
        "Bearer {}",
        raw.strip_prefix("Bearer ").unwrap_or(raw)
    ))
}

/// Validate the credential. **Nothing above the caller's use of this resolves a
/// credential or reaches an upstream** — `crates/gateway/CLAUDE.md`: "adding a
/// route without replicating that sequence ships an unauthenticated endpoint".
async fn authenticate(headers: &HeaderMap) -> Result<crate::auth::Claims, Response> {
    let Some(authorization) = authorization_value(headers) else {
        return Err(anthropic_error(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "missing credentials — send `x-api-key: tlane_…` or `Authorization: Bearer tlane_…`",
            &[],
        ));
    };
    match crate::auth::validate_authorization(&authorization).await {
        Ok(c) => Ok(c),
        Err(err) => {
            tracing::warn!(error = %err, "authentication failed");
            // B-391 (c): 503 `api_error` when the auth store is down, 401
            // `authentication_error` when the credential is wrong — the two
            // types Anthropic's own SDK distinguishes.
            let (status, msg) = crate::auth::failure(&err);
            let kind = if status == StatusCode::SERVICE_UNAVAILABLE {
                "api_error"
            } else {
                "authentication_error"
            };
            Err(anthropic_error(status, kind, msg, &[]))
        }
    }
}

/// A13 scope gate: `Some(refusal)` when this credential may not spend the tenant's
/// provider budget.
///
/// One definition so `/v1/messages` and `/v1/messages/count_tokens` cannot drift — a
/// `read`-scoped key is the shape `api_scope.rs` says to hand an external auditor,
/// and it must not be able to run up a bill on either. **`count_tokens` is gated
/// too**: it is not an inference, but it DOES decrypt and use the tenant's BYOK
/// credential, and a route that hands a credential to an upstream on a read-only key
/// is a hole regardless of how little it costs.
///
/// Called as the FIRST statement of the post-auth body on both routes, so a refusal
/// costs one comparison — no entitlement resolve, no quota read, no ledger row.
fn scope_refusal(claims: &crate::auth::Claims) -> Option<Response> {
    if claims.allows_scope(crate::auth::scope::Scope::Chat) {
        return None;
    }
    tracing::warn!(
        sub = %claims.sub,
        "api key lacks the `chat` scope — refusing the Anthropic Messages route"
    );
    Some(scope_refusal_response())
}

/// The A13 refusal body, shared by `count_tokens` (which gates inline) and the
/// admission pipeline's `Messages::refuse` — one wording on this wire.
fn scope_refusal_response() -> Response {
    anthropic_error(
        StatusCode::FORBIDDEN,
        "permission_error",
        "This API key is not scoped for completions. It needs the `chat` scope; \
         mint a new key with it in Settings → API Keys.",
        &[
            ("code", json!("insufficient_scope")),
            ("required_scope", json!("chat")),
        ],
    )
}

// ── Anthropic body → internal `ChatRequest` ──────────────────────────────────

/// Flatten an Anthropic `system` field (a string, or an array of content blocks)
/// into the internal single `system` string.
fn flatten_system(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Array(blocks) => {
            let joined: Vec<&str> = blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect();
            (!joined.is_empty()).then(|| joined.join("\n"))
        }
        _ => None,
    }
}

/// Translate one Anthropic message `content` (string or block array) into the
/// internal [`MessageContent`].
///
/// **This is a lossy read-model, on purpose.** Nothing built here is ever sent
/// upstream — the ORIGINAL bytes are — so the only consumers are the guardrail
/// rails, the predictive layer and `CapturedInput`. What they need is the text, the
/// tool definitions and the tool results; an `image` block's base64 payload is not
/// something a text rail can read, so it is dropped rather than smuggled in as a
/// fake URL. `thinking` blocks ARE kept as text: an assistant turn's reasoning is
/// content a leak rail should see.
fn translate_content(content: Option<&Value>) -> MessageContent {
    match content {
        Some(Value::String(s)) => MessageContent::Text(s.clone()),
        Some(Value::Array(blocks)) => {
            let mut parts: Vec<ContentPart> = Vec::with_capacity(blocks.len());
            for b in blocks {
                let cache_control = b.get("cache_control").cloned();
                match b.get("type").and_then(Value::as_str) {
                    Some("text") => parts.push(ContentPart::Text {
                        text: b
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        cache_control,
                    }),
                    Some("thinking") => parts.push(ContentPart::Text {
                        text: b
                            .get("thinking")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        cache_control: None,
                    }),
                    Some("tool_use") => parts.push(ContentPart::ToolUse {
                        id: b
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        name: b
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        input: b.get("input").cloned().unwrap_or(Value::Null),
                    }),
                    Some("tool_result") => parts.push(ContentPart::ToolResult {
                        tool_use_id: b
                            .get("tool_use_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        content: flatten_tool_result(b.get("content")),
                        cache_control,
                    }),
                    Some("image") => parts.push(capture_image_part(b)),
                    // Other blocks remain out of the read model; the original
                    // request still goes upstream byte-for-byte.
                    _ => {}
                }
            }
            MessageContent::Parts(parts)
        }
        _ => MessageContent::Text(String::new()),
    }
}

/// A `tool_result` block's `content` is a string OR an array of blocks. The rails
/// read it as one string; A5's untrusted-data wrap operates on the same field.
fn flatten_tool_result(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Build the internal [`ChatRequest`] the pre-dispatch stages evaluate.
///
/// Returns `Err(message)` only for a body that is not a Messages request at all
/// (no `model`, or `messages` that is not an array) — everything else degrades to
/// an empty read model rather than refusing a request Anthropic itself would
/// accept. Rejecting a legal request because our *read model* could not parse a
/// block is the failure this route exists to avoid.
fn to_chat_request(body: &Value) -> Result<ChatRequest, String> {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| "`model` is required".to_owned())?
        .to_owned();
    let raw_messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "`messages` is required and must be an array".to_owned())?;

    let mut messages = Vec::with_capacity(raw_messages.len());
    for m in raw_messages {
        let role = match m.get("role").and_then(Value::as_str) {
            Some("assistant") => Role::Assistant,
            // Anthropic has exactly two message roles; `system` is a top-level
            // field, not a role, and a tool result rides inside a user message.
            _ => Role::User,
        };
        messages.push(Message {
            role,
            content: translate_content(m.get("content")),
            tool_call_id: None,
            tool_calls: None,
        });
    }

    let tools = body.get("tools").and_then(Value::as_array).map(|ts| {
        ts.iter()
            .map(|t| Tool {
                name: t
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                description: t
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                input_schema: t
                    .get("input_schema")
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object", "properties": {} })),
            })
            .collect::<Vec<_>>()
    });

    Ok(ChatRequest {
        top_p: None,
        seed: None,
        logprobs: None,
        top_logprobs: None,
        model,
        messages,
        tools,
        // This is the pre-dispatch READ MODEL only — the `/v1/messages` route
        // forwards the caller's ORIGINAL body upstream, so a `tool_choice` on
        // that path is never dropped and never needs translating here.
        tool_choice: None,
        max_tokens: body
            .get("max_tokens")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        temperature: body
            .get("temperature")
            .and_then(Value::as_f64)
            .map(|t| t as f32),
        stream: body.get("stream").and_then(Value::as_bool),
        system: flatten_system(body.get("system")),
        metadata: None,
        ..Default::default()
    })
}

/// Is this an SSE request? Anthropic streams iff the body says `"stream": true`.
fn is_streaming(body: &Value) -> bool {
    body.get("stream").and_then(Value::as_bool) == Some(true)
}

// ── R2 request-side egress redaction, on the ORIGINAL bytes ──────────────────
//
// `guardrail::egress::redact_relay_body` (M-1, 2026-10-03): the ONE walk R2 scans this body
// with also rewrites it, and anything it cannot rewrite blocks. It replaced a per-wire copy
// here that rewrote only `system` and message text — so a secret R2 flagged in a tool
// description was "redacted" in the verdict and still sent in the bytes.

// ── Upstream client ──────────────────────────────────────────────────────────

/// One process-wide client, so a relayed request reuses the connection pool
/// instead of paying a fresh TLS handshake per call — the difference between
/// "the same pipeline" and "the same pipeline plus 40 ms".
///
/// SSRF: built from `safe_client_builder` (redirects disabled), and every URL is
/// still `validate_url`'d before the POST.
///
/// # Errors
/// **Fail-CLOSED.** `Err` only if reqwest cannot build a client at all (a broken TLS
/// backend). The caller turns that into `502 provider_unavailable` rather than
/// falling back to an unguarded client — an SSRF guard you can lose under load is
/// not a guard.
fn upstream_client() -> anyhow::Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let built = crate::ssrf_guard::safe_client_builder()
        .timeout(std::time::Duration::from_secs(UPSTREAM_TIMEOUT_SECS))
        .build()?;
    Ok(CLIENT.get_or_init(|| built))
}

/// The client's `anthropic-version` / `anthropic-beta`, passed through untouched.
///
/// **Pass-through, not pinned.** `providers/anthropic.rs` pins `2023-06-01` +
/// `interleaved-thinking-2025-05-14` because it builds the request itself and must
/// know what shape it will get back. Here the caller built the request, so pinning
/// our own beta set would silently change the response shape from under an SDK that
/// asked for something else. Values are copied verbatim and only when the header is
/// valid ASCII — a malformed header is dropped rather than forwarded, so it cannot
/// be used to smuggle a second header through.
fn passthrough_version_headers(
    headers: &HeaderMap,
    req: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    let version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_ANTHROPIC_VERSION);
    let mut req = req.header("anthropic-version", version);
    if let Some(beta) = headers.get("anthropic-beta").and_then(|v| v.to_str().ok()) {
        req = req.header("anthropic-beta", beta);
    }
    req
}

/// Classify an upstream status into `(our status, code, message)` — the SAME
/// vocabulary `chat_completions_handler` uses, so one grep covers both wires.
///
/// **OG-10 §3.1 (D7): this is now the CLASSIFICATION, and the response for only
/// 401/403/407.** Those bodies can echo the `x-api-key` header value, which would put
/// the customer's BYOK key in our response and in anything that logs it
/// (`providers/anthropic.rs` says the same at its own error site), so they keep
/// the `provider_key_rejected` mapping and their body is dropped. Every OTHER error
/// status is relayed with its original status and (scrubbed) body by
/// [`upstream_error_response`]; the code returned here is then only the ledger / span
/// reason (`dispatch_guard.abort`).
fn map_upstream_status(status: u16) -> (StatusCode, &'static str, &'static str) {
    match status {
        401 | 403 | 407 => (
            StatusCode::UNAUTHORIZED,
            "provider_key_rejected",
            "the stored Anthropic key was rejected by Anthropic — verify or rotate it in Settings → LLM providers",
        ),
        404 => (
            StatusCode::NOT_FOUND,
            "model_not_found",
            "Anthropic does not recognise this model for this account — check the model name and that your account has access to it",
        ),
        429 => (
            StatusCode::TOO_MANY_REQUESTS,
            "provider_rate_limited",
            "Anthropic rate-limited or quota-exhausted this request — retry later, or check the provider account's plan and billing",
        ),
        413 => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "provider_request_rejected",
            "Anthropic rejected this request as too large",
        ),
        s if (400..500).contains(&s) => (
            StatusCode::BAD_REQUEST,
            "provider_request_rejected",
            "Anthropic rejected this request. This is not a Tracelane outage — it is usually a key that is invalid for this account, or a request Anthropic could not accept (model, parameters, or payload)",
        ),
        _ => (
            StatusCode::BAD_GATEWAY,
            "provider_unavailable",
            "Anthropic did not serve this request",
        ),
    }
}

/// Whether an upstream failure is an observation about ANTHROPIC's health. Re-exported
/// rather than restated: two copies of this rule are how a change to one (F4, 429)
/// would have left the other tripping.
#[cfg(test)]
pub(crate) use crate::openai_responses::breaker_observation;

// ── Usage accumulation ───────────────────────────────────────────────────────

/// Token usage merged out of the Anthropic response, streamed or buffered.
///
/// **Merged with MAX, the B-104 rule.** `message_start` carries `input_tokens` +
/// the cache counters with `output_tokens: 0`; `message_delta` carries the final
/// `output_tokens` with no input. Summing would double-count on a provider that
/// repeats a field; taking the max of each counter independently is what makes the
/// two events compose into one truth.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UsageAcc {
    pub(crate) input: u32,
    pub(crate) output: u32,
    pub(crate) cache_read: Option<u32>,
    pub(crate) cache_creation: Option<u32>,
}

impl UsageAcc {
    /// Fold an Anthropic `usage` object (from `message_start.message.usage`,
    /// `message_delta.usage`, or a non-streamed body's `usage`) into the running
    /// totals.
    fn merge(&mut self, usage: &Value) {
        let read = |k: &str| {
            usage
                .get(k)
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
        };
        if let Some(v) = read("input_tokens") {
            self.input = self.input.max(v);
        }
        if let Some(v) = read("output_tokens") {
            self.output = self.output.max(v);
        }
        if let Some(v) = read("cache_read_input_tokens") {
            self.cache_read = Some(self.cache_read.unwrap_or(0).max(v));
        }
        if let Some(v) = read("cache_creation_input_tokens") {
            self.cache_creation = Some(self.cache_creation.unwrap_or(0).max(v));
        }
    }

    /// The shared `Usage` the guardrail rails (R1's output cap) and
    /// `pricing::cost_usd` both read.
    pub(crate) fn as_usage(self) -> Usage {
        Usage {
            input_tokens: self.input,
            output_tokens: self.output,
            cache_read_input_tokens: self.cache_read,
            cache_creation_input_tokens: self.cache_creation,
        }
    }
}

// ── SSE frame splitting ──────────────────────────────────────────────────────

/// One SSE frame, verbatim, plus what the relay needs to know about it.
pub(crate) struct Frame {
    /// The frame's ORIGINAL bytes, terminator included. Relayed unchanged on the
    /// clean path — this is the byte-fidelity guarantee, held as data rather than
    /// reconstructed.
    pub(crate) raw: Bytes,
    /// `Some(text)` iff this frame is a `content_block_delta` carrying a
    /// `text_delta`. Only these go through the response seam: `thinking_delta` and
    /// `input_json_delta` are not model prose the response rails are written for,
    /// and re-chunking a partial JSON tool argument would corrupt it.
    pub(crate) text: Option<String>,
    /// `content_block` index of a text delta, so a rewritten frame lands on the
    /// same block the provider was writing into.
    pub(crate) index: u64,
}

/// Split off the first complete SSE frame in `buf`, returning its bytes (including
/// the blank-line terminator). `None` when no complete frame is buffered yet.
///
/// Handles BOTH `\n\n` and `\r\n\r\n`: Anthropic sends the former, but a proxy in
/// front of a self-hosted endpoint may normalise line endings, and a splitter that
/// only knows one of them would buffer the entire response and emit it at once —
/// which looks exactly like a hung stream.
pub(crate) fn split_frame(buf: &mut Vec<u8>) -> Option<Bytes> {
    let lf = find_sub(buf, b"\n\n");
    let crlf = find_sub(buf, b"\r\n\r\n");
    let (end, _) = match (lf, crlf) {
        (Some(a), Some(b)) if a <= b => (a + 2, 2),
        (Some(_), Some(b)) => (b + 4, 4),
        (Some(a), None) => (a + 2, 2),
        (None, Some(b)) => (b + 4, 4),
        (None, None) => return None,
    };
    let frame: Vec<u8> = buf.drain(..end).collect();
    Some(Bytes::from(frame))
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The `data:` payload of an SSE frame, if it has one.
pub(crate) fn frame_data(raw: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(raw).ok()?;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(rest) = line.strip_prefix("data:") {
            return Some(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    None
}

/// Synthesise a `content_block_delta` frame carrying guard-transformed text.
///
/// Only reached once a rail has redacted — see [`Relay`]. The frame is valid
/// Anthropic SSE, so an SDK keeps parsing; what it is NOT is byte-identical, which
/// is the deliberate trade.
fn synth_text_delta(index: u64, text: &str) -> Bytes {
    let payload = json!({
        "type": "content_block_delta",
        "index": index,
        "delta": { "type": "text_delta", "text": text },
    });
    Bytes::from(format!("event: content_block_delta\ndata: {payload}\n\n"))
}

/// The terminal frame for a guardrail block: an Anthropic `error` event carrying
/// our correlation id, then nothing more.
///
/// Anthropic's own streams end an interrupted response with `event: error`, so an
/// SDK already knows how to surface this. The held-back tail — which holds the
/// offending content — is dropped, never flushed.
fn synth_block_error(reason_code: &str, correlation_id: &str) -> Bytes {
    let payload = json!({
        "type": "error",
        "error": {
            "type": "permission_error",
            "message": "response blocked by Tracelane inline guardrail",
            "code": "guardrail_block",
            "reason_code": reason_code,
            "correlation_id": correlation_id,
        },
    });
    Bytes::from(format!("event: error\ndata: {payload}\n\n"))
}

// ── The relay ────────────────────────────────────────────────────────────────

/// Holds raw provider frames until the response seam has cleared the text they
/// carry, then releases them **verbatim**.
///
/// ## The invariant
///
/// A frame is released byte-for-byte only when the guard has emitted safe text
/// covering that frame's text AND that safe text is byte-identical to what the
/// provider sent over the same range. So:
///
/// * **Nothing redacted (the default, and every free/builder tenant):** every frame
///   goes out unchanged, in order, delayed by the guard's 512-char hold-back.
/// * **A rail redacts:** the relay flips to `rewriting` permanently. Raw text frames
///   are dropped and the guard's transformed text is synthesised into
///   `content_block_delta` frames instead. Byte fidelity is gone for the rest of the
///   stream — deliberately. It is the weaker of the two properties and the one that
///   must yield.
/// * **A rail blocks:** every held frame is dropped and the stream ends with an
///   Anthropic `error` event.
///
/// Non-text frames (`message_start`, `content_block_start`, `thinking_delta`,
/// `input_json_delta`, `ping`, `message_delta`, `message_stop`) queue in order
/// behind any pending text frame, so ordering is never re-arranged.
pub(crate) struct Relay {
    guard: crate::guardrail::ResponseGuard,
    pending: std::collections::VecDeque<Frame>,
    /// Every text delta the provider sent, concatenated.
    raw_text: String,
    /// Every safe chunk the guard released, concatenated.
    safe_text: String,
    /// Bytes of `raw_text` already covered by released frames.
    released: usize,
    /// Bytes of `safe_text` already synthesised (only moves in `rewriting`).
    synthesised: usize,
    rewriting: bool,
    last_index: u64,
    /// Builds the frame that carries guard-transformed text once a rail has redacted. The
    /// Anthropic wire's is a `content_block_delta`; `gemini_native` supplies its own.
    synth: fn(u64, &str) -> Bytes,
}

/// What the relay wants the caller to do next.
pub(crate) enum Release {
    /// Send these bytes to the client, in order.
    Bytes(Vec<Bytes>),
    /// A rail blocked: send these bytes (the block frame) and end the stream.
    Blocked(Vec<Bytes>, &'static str),
}

impl Relay {
    pub(crate) fn new(guard: crate::guardrail::ResponseGuard) -> Self {
        Self::with_synth(guard, synth_text_delta)
    }

    /// [`Relay::new`] for a wire with its own text-frame shape.
    pub(crate) fn with_synth(
        guard: crate::guardrail::ResponseGuard,
        synth: fn(u64, &str) -> Bytes,
    ) -> Self {
        Self {
            guard,
            pending: std::collections::VecDeque::new(),
            raw_text: String::new(),
            safe_text: String::new(),
            released: 0,
            synthesised: 0,
            rewriting: false,
            last_index: 0,
            synth,
        }
    }

    /// Feed one provider frame. Returns whatever became releasable.
    pub(crate) async fn push(&mut self, frame: Frame, usage: Usage) -> Release {
        let scanned = frame.text.as_deref().unwrap_or("");
        let unscanned = frame_data(&frame.raw)
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .as_ref()
            .is_some_and(|v| {
                crate::guardrail::streaming::has_unscanned_output(v)
                    || crate::guardrail::streaming::has_unseen_text(v, scanned)
            });
        if unscanned && let Some(reason) = self.guard.refuse_unscanned_output().await {
            self.pending.clear();
            return Release::Blocked(Vec::new(), reason);
        }
        if let Some(text) = frame.text.clone() {
            self.last_index = frame.index;
            self.raw_text.push_str(&text);
            self.pending.push_back(frame);
            match self.guard.on_delta(&text, Some(&usage)).await {
                crate::guardrail::GuardStep::Emit(safe) => self.safe_text.push_str(&safe),
                crate::guardrail::GuardStep::Block { reason_code } => {
                    self.pending.clear();
                    return Release::Blocked(Vec::new(), reason_code);
                }
            }
        } else {
            self.pending.push_back(frame);
        }
        Release::Bytes(self.drain())
    }

    /// The provider stream ended. Flush the guard's held-back tail and everything
    /// still queued.
    pub(crate) async fn finish(&mut self, usage: Usage) -> Release {
        match self.guard.on_end(Some(&usage)).await {
            crate::guardrail::GuardStep::Emit(safe) => self.safe_text.push_str(&safe),
            crate::guardrail::GuardStep::Block { reason_code } => {
                self.pending.clear();
                return Release::Blocked(Vec::new(), reason_code);
            }
        }
        Release::Bytes(self.drain())
    }

    /// Release every frame at the head of the queue that is now safe.
    fn drain(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        while let Some(front) = self.pending.front() {
            let Some(text) = front.text.as_ref() else {
                // A non-text frame at the head is always releasable: everything
                // before it has already gone out.
                if let Some(f) = self.pending.pop_front() {
                    out.push(f.raw);
                }
                continue;
            };
            if self.rewriting {
                // Its text is carried by `safe_text` instead; drop the raw frame.
                self.pending.pop_front();
                continue;
            }
            let end = self.released + text.len();
            if end > self.safe_text.len() {
                break; // still inside the guard's hold-back
            }
            if self.safe_text.as_bytes()[self.released..end]
                == self.raw_text.as_bytes()[self.released..end]
            {
                self.released = end;
                if let Some(f) = self.pending.pop_front() {
                    out.push(f.raw);
                }
                continue;
            }
            // DIVERGENCE — a rail rewrote text that is now due for release. From
            // here the stream is synthesised, permanently: re-aligning raw frames
            // to a transformed buffer whose LENGTH has changed is not a mapping
            // that exists, and guessing at one is how redacted bytes escape.
            self.rewriting = true;
            self.synthesised = self.released;
        }
        if self.rewriting && self.safe_text.len() > self.synthesised {
            out.push((self.synth)(
                self.last_index,
                &self.safe_text[self.synthesised..],
            ));
            self.synthesised = self.safe_text.len();
        }
        out
    }
}

// ── `POST /v1/messages` ──────────────────────────────────────────────────────

/// The Anthropic Messages route's contribution to the ONE admission pipeline
/// (`crate::admission`, B-385): its credential header, its body shape, its
/// ledger payload and its wire's rendering of each refusal.
pub(crate) struct Messages;

/// What PARSE produced: the caller's ORIGINAL bytes (they are what egresses,
/// byte-for-byte, unless R2 redacts), the parsed JSON (the predictors, the R2
/// redaction and the guardrail RAG context read it), and the internal
/// `ChatRequest` the rails and the span are defined over.
pub(crate) struct MessagesParsed {
    pub raw: Bytes,
    pub json_body: Value,
    pub chat_request: ChatRequest,
    /// `OG-11`: the model routes nowhere by the provider map — it may be one of the
    /// workspace's virtual models, which only the entitlement read knows. The parse
    /// defers its `unroutable_model` refusal to `apply_route` (still before any charge).
    pub unresolved: bool,
    /// `OG-11`: `apply_route` rewrote `model` to a virtual model's target, so the
    /// caller's bytes no longer egress verbatim — `json_body` is re-serialised.
    pub rerouted: bool,
}

/// The refusal for a model this wire cannot route (a parse refusal, or one `apply_route`
/// raises once the workspace's virtual models are known not to name it).
fn unroutable_on_messages() -> crate::admission::Malformed {
    crate::admission::Malformed {
        code: "unroutable_model",
        message: "POST /v1/messages serves Anthropic models only — use a `claude-*` \
                  model here, or POST /v1/chat/completions for any other provider"
            .into(),
        detail: None,
    }
}

impl crate::admission::Parsed for MessagesParsed {
    fn model(&self) -> &str {
        &self.chat_request.model
    }
    fn request_json(&self) -> &Value {
        &self.json_body
    }
    /// `OG-20`: one generating call (`max_tokens` is required on this wire).
    fn policy_request(&self) -> tracelane_shared::key_policy::PolicyRequest {
        tracelane_shared::key_policy::PolicyRequest {
            subjects: vec![crate::admission::chat_subject(
                &self.chat_request,
                false,
                None,
            )],
            body_bytes: tracelane_shared::key_policy::Fact::Known(self.raw.len() as u64),
        }
    }
}

impl crate::admission::Route for Messages {
    type Body = Bytes;
    type Parsed = MessagesParsed;
    const NAME: &'static str = "messages";
    const AUDIT_EVENT_TYPE: &'static str = "messages.request";
    const CACHE: crate::admission::CacheScope = crate::admission::CacheScope::Refuses;
    // OG-11 (a native relay: only Anthropic targets of a virtual model, fallthrough within Anthropic).
    const ROUTING: crate::routing::RoutingScope = crate::routing::RoutingScope {
        wire: crate::routing::Wire::Messages,
        virtual_models: crate::routing::VirtualSupport::OwnProvider(PROVIDER_ID),
        key_pool: crate::routing::PoolSupport::Pool,
        fallthrough: true,
        timeouts: true,
    };

    /// `Authorization` OR `x-api-key` — the two headers Anthropic's SDKs send.
    fn credential(headers: &HeaderMap) -> Option<String> {
        authorization_value(headers)
    }

    /// `OG-11`: a virtual model (Anthropic targets only — the plan refused any other)
    /// becomes its first candidate; an unroutable name no plan resolved is refused.
    fn apply_route(
        parsed: &mut MessagesParsed,
        plan: Option<&mut crate::routing::RoutePlan>,
    ) -> Result<(), crate::admission::Malformed> {
        match plan.and_then(|p| p.candidates.first()) {
            Some(c) => {
                parsed.chat_request.model.clone_from(&c.model);
                parsed.json_body["model"] = Value::String(c.model.clone());
                parsed.unresolved = false;
                parsed.rerouted = true;
                Ok(())
            }
            None if parsed.unresolved => Err(unroutable_on_messages()),
            None => Ok(()),
        }
    }

    /// Parse, translate, and ROUTE. ONE WIRE, ONE PROVIDER (spec §6): a `gpt-*`
    /// model on this endpoint is not a routing problem to solve by translating
    /// — it is a caller mistake, and answering it by silently rewriting the
    /// request into OpenAI's shape would return a body the Anthropic SDK cannot
    /// parse. Refused by name HERE, inside the parse step, so it sits where it
    /// always did: before any entitlement resolve, quota read or credential.
    fn parse(body: Bytes) -> Result<MessagesParsed, crate::admission::Malformed> {
        // M-A: the STRICT parse — the caller's bytes are what egress, so a key repeated in
        // any object (scanned on one copy, read by the provider on another) is refused here.
        let json_body = crate::strict_json::from_slice(&body)
            .map_err(|e| e.into_malformed("request body is not valid JSON"))?;
        let chat_request =
            to_chat_request(&json_body).map_err(|message| crate::admission::Malformed {
                code: "invalid_request",
                message,
                detail: None,
            })?;
        // A model ANOTHER provider serves is a caller mistake, refused here as always. A
        // model nothing routes may be a workspace virtual model (OG-11): `apply_route`
        // resolves it or refuses it with the same error, before any charge.
        let unresolved =
            match crate::providers::ProviderRegistry::provider_id_for_model(&chat_request.model) {
                Some(PROVIDER_ID) => false,
                Some(_) => return Err(unroutable_on_messages()),
                None => true,
            };
        Ok(MessagesParsed {
            raw: body,
            json_body,
            chat_request,
            unresolved,
            rerouted: false,
        })
    }

    /// The SHAPE — never the prompt: the ledger is exported to third parties.
    fn audit_payload(
        parsed: &MessagesParsed,
        trace_id: Uuid,
        warn_aft_id: Option<&'static str>,
    ) -> Value {
        json!({
            "model": parsed.chat_request.model,
            "warn_aft_id": warn_aft_id,
            "stream": is_streaming(&parsed.json_body),
            "trace_id": trace_id,
        })
    }

    /// Every refusal, Anthropic-shaped — the bodies this route always sent.
    fn refuse(refusal: crate::admission::Refusal) -> Response {
        use crate::admission::Refusal;
        let status = refusal.status();
        match refusal {
            Refusal::MissingCredentials => anthropic_error(
                status,
                "authentication_error",
                "missing credentials — send `x-api-key: tlane_…` or `Authorization: Bearer tlane_…`",
                &[],
            ),
            Refusal::AuthFailed { message, .. } => {
                // B-391 (c): 503 `api_error` when the auth store is down, 401
                // `authentication_error` when the credential is wrong — the two
                // types Anthropic's own SDK distinguishes.
                let kind = if status == StatusCode::SERVICE_UNAVAILABLE {
                    "api_error"
                } else {
                    "authentication_error"
                };
                anthropic_error(status, kind, message, &[])
            }
            Refusal::InsufficientScope => scope_refusal_response(),
            Refusal::Malformed(crate::admission::Malformed { code, message, .. }) => {
                coded_error(status, code, &message)
            }
            Refusal::RateLimited { retry_after_secs } => {
                let mut resp = anthropic_error(
                    status,
                    "rate_limit_error",
                    "rate limit exceeded",
                    &[
                        ("code", json!("rate_limited")),
                        ("retry_after_secs", json!(retry_after_secs)),
                    ],
                );
                crate::admission::insert_retry_after(&mut resp, retry_after_secs);
                resp
            }
            Refusal::KeyBudgetExceeded {
                budget_usd,
                spent_usd,
            } => budget_error("key_budget_exceeded", budget_usd, spent_usd),
            Refusal::WorkspaceBudgetExceeded {
                budget_usd,
                spent_usd,
            } => budget_error("workspace_budget_exceeded", budget_usd, spent_usd),
            Refusal::PredictiveBlock { aft_id } => anthropic_error(
                status,
                "permission_error",
                "request blocked by Tracelane predictive guardrail",
                &[
                    ("code", json!("predictive_block")),
                    ("aft_id", json!(aft_id)),
                ],
            ),
            Refusal::AuditUnavailable => coded_error(
                status,
                "audit_unavailable",
                "the tamper-evident ledger is unavailable — this request was not served because it could not be recorded",
            ),
            Refusal::Unpriced { code, message } => coded_error(status, code, &message),
            Refusal::Policy(d) => {
                let mut extra = crate::admission::policy_pairs(&d);
                extra.push(("code", json!(d.code)));
                anthropic_error(status, error_type_for(status), &d.message, &extra)
            }
            Refusal::Control(c) => {
                let mut extra = c.detail.clone();
                extra.push(("code", json!(c.code)));
                c.finish(anthropic_error(
                    status,
                    error_type_for(status),
                    &c.message,
                    &extra,
                ))
            }
        }
    }
}

/// Anthropic Messages — the same pipeline, the wire Claude Code speaks.
///
/// Takes the body as raw [`Bytes`], not `Json<Value>`: the bytes ARE the request
/// that goes upstream, and an axum `Json` extractor would have re-serialised them
/// (dropping key order, number formatting and any field our types do not model).
///
/// # Errors
/// Every refusal is Anthropic-shaped. Fail-CLOSED: auth, scope, routing, the audit
/// publish (`503 audit_unavailable`), provider-key resolution and the request-side
/// guardrail verdict all refuse rather than proceed. Fail-OPEN: span publish,
/// byte metering and spend recording are off the response path — a NATS or
/// ClickHouse fault never fails a request Anthropic served.
#[instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
pub async fn messages_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let labels = crate::server::request_labels::read(
        &headers,
        &state.rate_card.load().policy.request_labels,
    );
    let result = messages_with_labels(State(state), headers, body, &labels).await;
    crate::server::request_labels::response(result, &labels)
}

async fn messages_with_labels(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
    labels: &crate::server::request_labels::BoundedLabels,
) -> Response {
    use crate::admission::Route as _;
    let control = match crate::semantic_cache::CacheControl::parse(&headers) {
        Ok(control) => control,
        Err(err) => return err.response(true),
    };
    match crate::admission::admit::<Messages>(&state, &headers, body).await {
        Ok(mut admitted) => {
            crate::server::request_labels::attach(&mut admitted, labels);
            let policy = match control.resolve(
                admitted.entitlements.as_deref(),
                state.semantic_cache.as_deref(),
                false,
                &crate::cache_controls::CacheCaller::default(),
            ) {
                Ok(policy) => policy,
                Err(err) => {
                    admitted.dispatch_guard.abort(err.code, None);
                    return err.response(true);
                }
            };
            policy.response(messages_admitted(state, headers, admitted).await)
        }
        Err(refusal) => Messages::refuse(refusal),
    }
}

/// The pipeline from the scope gate down, with a caller-supplied credential.
/// TEST-ONLY: `validate_authorization` reads Postgres or WorkOS, so a `read`-only
/// key is not constructible through it in a unit test, and the A13 refusal would
/// have gone unproven — asserted by description rather than by a run, which is
/// the class `CLAUDE.md` §1 exists to stop. Production has exactly ONE path into
/// the pipeline: [`messages_handler`] → `admission::admit`.
#[cfg(test)]
pub(crate) async fn messages_with_claims(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    claims: crate::auth::Claims,
) -> Response {
    use crate::admission::Route as _;
    match crate::admission::admit_with_claims::<Messages>(&state, &headers, body, claims).await {
        Ok(admitted) => messages_admitted(state, headers, admitted).await,
        Err(refusal) => Messages::refuse(refusal),
    }
}

/// Everything after admission: BYOK → request guardrails → breaker → forward →
/// relay. Every exit has a ledger row behind it, so every refusal goes through
/// `dispatch_guard.abort` (records the error span, R13) and the two success
/// paths `disarm` once they own the record.
async fn messages_admitted(
    state: AppState,
    headers: HeaderMap,
    admitted: crate::admission::Admitted<Messages>,
) -> Response {
    let crate::admission::Admitted {
        attempt_security,
        claims,
        mut identity,
        request_start,
        trace_id,
        inbound_parent,
        parsed,
        warn_aft_id,
        correlation_id,
        mut dispatch_guard,
        // B-568 I2: kept, not discarded in the `..` — this route (the one Claude
        // Code uses) had no stage breakdown anywhere until 2026-09-27.
        mut timer,
        entitlements,
        route_plan,
        ..
    } = admitted;
    // GWY-53: the ONE capture decision (operator allowlist OR the workspace opt-in;
    // no control plane = the workspace half OFF). This route records the REQUEST text
    // only — its response capture is not built yet (spec §6).
    let capture = crate::server::config::capture_decision(
        crate::server::config::trace_content(),
        entitlements.as_deref().map(|e| e.content_capture),
        &claims.tenant_id,
    );
    let MessagesParsed {
        raw: body,
        mut json_body,
        chat_request,
        rerouted,
        ..
    } = parsed;
    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());
    let mut model = chat_request.model.clone(); // Error spans retain the admitted input.
    dispatch_guard.record_input(CapturedInput::build(capture, &chat_request));
    // OG-11: the targets (a virtual model's Anthropic models, in plan order; else the one
    // model asked for) and the routing facts for the span.
    let targets: Vec<String> = route_plan
        .as_deref()
        .filter(|p| p.dispatches())
        .map_or_else(
            || vec![model.clone()],
            |p| p.candidates.iter().map(|c| c.model.clone()).collect(),
        );
    identity.route = crate::server::RouteMeta::from_plan(route_plan.as_deref());
    dispatch_guard.record_route(identity.route.clone());
    // Kept as a local because this route feeds it to the guardrail
    // `SessionState` independently of the span.
    let conversation_id = identity.conversation_id.clone();

    // GWY-49: the zero-data-retention constraint. This route has ONE provider
    // (`PROVIDER_ID`) and no failover chain, so the check is that provider's capability
    // and the eligible set is it or nothing; the same header, the same fail-CLOSED
    // refusal as `/v1/chat/completions`, before any credential is resolved or a byte leaves — in THIS wire's
    // error shape (`coded_error`), because a Claude SDK cannot read an OpenAI body.
    let zdr_eligible: Option<Vec<String>> = match crate::zdr::constraint_from_headers(&headers) {
        Ok(None) => None,
        Ok(Some(crate::zdr::Constraint::Required)) => {
            let caps = state.zdr.load();
            if !caps.eligible(PROVIDER_ID) {
                dispatch_guard.record_zdr(Vec::new());
                dispatch_guard.abort("zdr_unsatisfiable", None);
                return anthropic_error(
                    StatusCode::BAD_REQUEST,
                    error_type_for(StatusCode::BAD_REQUEST),
                    &crate::server::zdr_unsatisfiable_message(caps.default_count()),
                    &[
                        ("code", json!("zdr_unsatisfiable")),
                        ("model", json!(chat_request.model)),
                        ("provider", json!(PROVIDER_ID)),
                        ("eligible_provider_count", json!(caps.default_count())),
                    ],
                );
            }
            let eligible = vec![PROVIDER_ID.to_string()];
            dispatch_guard.record_zdr(eligible.clone());
            Some(eligible)
        }
        Err(bad) => {
            dispatch_guard.abort("invalid_zdr_constraint", None);
            return anthropic_error(
                StatusCode::BAD_REQUEST,
                error_type_for(StatusCode::BAD_REQUEST),
                crate::server::INVALID_ZDR_CONSTRAINT_MESSAGE,
                &[
                    ("code", json!("invalid_zdr_constraint")),
                    ("received", json!(bad.chars().take(64).collect::<String>())),
                ],
            );
        }
    };

    // --- Step 2: BYOK. Fail-CLOSED, and the two failures need OPPOSITE actions ---
    // OG-11: from Anthropic's key POOL when the routing document gives it one (the
    // first label whose key resolves; the rest serve a key failure), else `default`.
    let routing_state: std::sync::Arc<crate::routing::RoutingState> = entitlements
        .as_deref()
        .map(|e| std::sync::Arc::clone(&e.routing))
        .unwrap_or_default();
    let mut route_rng = crate::routing::thread_rng;
    let pool = crate::routing::pool_labels(
        &Messages::ROUTING,
        &routing_state,
        PROVIDER_ID,
        &mut route_rng,
    );
    let pooled = pool.pooled;
    let mut key_cursor = crate::server::KeyCursor::new(pool.labels);
    let key_env = crate::providers::ProviderRegistry::env_var_for_provider_id(PROVIDER_ID);
    let mut first_key: Option<(String, std::sync::Arc<secrecy::SecretString>)> = None;
    while let Some((label, k)) = key_cursor.next_key(tenant_id, PROVIDER_ID, key_env).await {
        if !k.expose_secret().is_empty() {
            first_key = Some((label, k));
            break;
        }
    }
    // B-568 I5: a BYOK cache miss read the control plane on the request path.
    if key_cursor.cold {
        timer.note_cold();
        identity.cold_start = true;
    }
    let first_key = match first_key {
        Some(k) => k,
        None => {
            let (status, code, message) = match key_cursor.into_failure() {
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
                ProviderKey::Unusable => (
                    StatusCode::BAD_GATEWAY,
                    "provider_key_unusable",
                    "a stored Anthropic key could not be decrypted — rotate it in Settings → LLM providers",
                ),
                ProviderKey::LookupFailed => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "provider_key_unavailable",
                    "the key store could not be reached — nothing was sent to Anthropic; retry shortly",
                ),
                // An empty key reaches here too: Anthropic is not a no-key provider,
                // so an empty credential is "not configured", never "use it anyway".
                ProviderKey::NotConfigured | ProviderKey::Found(_) => (
                    StatusCode::PAYMENT_REQUIRED,
                    "provider_not_configured",
                    "no Anthropic key stored for this workspace — add one in Settings → LLM providers, then retry",
                ),
            };
            tracing::warn!(provider = PROVIDER_ID, code, "provider key unresolvable");
            dispatch_guard.abort(code, None);
            return coded_error(status, code, message);
        }
    };
    timer.mark("route_byok");

    // --- Step 3: Inline guardrails, request side. Fail-CLOSED ---
    // `correlation_id` was minted by admission; the response-side seam reuses it.
    let mut redaction_map: Vec<RedactionEntry> = Vec::new();
    let request_hooks;
    let mut hooks_rewrote = false;
    {
        let mut gr = state
            .guardrail
            .evaluate_request(crate::guardrail::RequestInputs {
                tenant_id,
                api_key_id: claims.api_key_id(),
                project_id: claims.governance.as_ref().and_then(|g| g.project_id),
                correlation_id,
                request: &chat_request,
                rag_context: crate::guardrail::context::extract_rag_context(&json_body),
                session: crate::guardrail::SessionState::fresh(conversation_id.clone()),
                actor: claims.sub.as_str(),
                egress_json: Some(&json_body),
            })
            .await;
        request_hooks = gr.hooks.clone();
        identity.hook_events.record(&gr.hook_events);
        if !gr.is_block() && !gr.hook_redactions.is_empty() {
            let rewritten =
                crate::guardrail::egress::redact_hook_json(&mut json_body, &gr.hook_redactions);
            match rewritten {
                Ok(()) => {
                    hooks_rewrote = true;
                }
                Err(_) => {
                    crate::guardrail::hooks::block(&mut gr.outcome, "HOOK_REDACTION_UNSUPPORTED")
                }
            }
        }
        if gr.audit_publish_failed {
            tracing::error!(
                correlation_id = %correlation_id,
                "guardrail verdict audit publish failed — refusing request (fail-closed)"
            );
            dispatch_guard.abort("audit_unavailable", None);
            return coded_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "the guardrail verdict could not be recorded — this request was not served",
            );
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
            dispatch_guard.abort(
                "guardrail_block",
                crate::guardrail::rails::r3_tool_safety::reason_to_aft(reason),
            );
            return anthropic_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                "request blocked by Tracelane inline guardrail",
                &[
                    ("code", json!("guardrail_block")),
                    ("rail", json!(rail)),
                    ("reason_code", json!(reason)),
                    ("correlation_id", json!(correlation_id.to_string())),
                ],
            );
        }
        if gr.outcome.records.iter().any(|r| {
            r.rail == "R2_secrets_pii" && r.outcome.outcome == crate::guardrail::Outcome::Redact
        }) {
            // M-1: the SAME walk R2 scanned the body with rewrites it; anything it cannot
            // rewrite in place is refused, never forwarded (fail-CLOSED, §10).
            match crate::guardrail::egress::redact_relay_body_with_policy(
                &mut json_body,
                gr.pii_policy.as_ref(),
            ) {
                Ok(map) => redaction_map = map,
                Err(crate::guardrail::egress::Unredactable) => {
                    tracing::warn!(correlation_id = %correlation_id, "R2 redact could not cover the egress body — blocking; raw capture cleared");
                    dispatch_guard.record_input(None);
                    dispatch_guard.abort("guardrail_block", None);
                    return anthropic_error(
                        StatusCode::FORBIDDEN,
                        "permission_error",
                        "request blocked by Tracelane inline guardrail: a secret sits where the gateway cannot redact it in place",
                        &[
                            ("code", json!("guardrail_block")),
                            ("rail", json!(crate::guardrail::egress::UNREDACTABLE_RAIL)),
                            (
                                "reason_code",
                                json!(crate::guardrail::egress::UNREDACTABLE_REASON),
                            ),
                            ("correlation_id", json!(correlation_id.to_string())),
                        ],
                    );
                }
            }
        }
    } // Capture the exact redacted request that may leave the gateway.

    let captured_input = if redaction_map.is_empty() {
        CapturedInput::build(capture, &chat_request)
    } else {
        to_chat_request(&json_body)
            .ok()
            .and_then(|safe| CapturedInput::build(capture, &safe))
    };
    dispatch_guard.record_input(captured_input.clone());

    // --- Step 4: kill switch (ADR-038) — provider-wide, before any attempt ---
    // OG-13: the adapter's region; each pool key is its own breaker credential, checked
    // per attempt inside the relay loop.
    let region = state.providers.upstream_region(PROVIDER_ID).to_owned();
    let killed = state.kill_switch.upstream_killed(PROVIDER_ID);
    if killed {
        tracing::warn!(
            provider = PROVIDER_ID,
            killed,
            "upstream unavailable (killed) — short-circuiting with 503"
        );
        dispatch_guard.abort("upstream_killed", None);
        return overloaded_response();
    }

    // --- Step 5: Forward. Same-provider only: a virtual model's NEXT Anthropic target
    // on a 5xx / transport failure, the NEXT pool key on a 401/403/429 (OG-11) ---
    // B-568 I2: guardrails + the egress body, then the dispatch boundary — emitted
    // against the same `dispatch_ts - request_start` the span's overhead number opens
    // with, exactly as the chat route does.
    timer.mark("guardrails");
    let dispatch_ts = chrono::Utc::now();
    timer.emit_if_slow(
        &state.hotpath,
        u64::try_from(
            (dispatch_ts - request_start)
                .num_microseconds()
                .unwrap_or(0),
        )
        .unwrap_or(0),
    );
    // The bytes that actually egress. Unchanged — the SAME allocation — unless R2
    // redacted, or a virtual model's target replaced `model` (OG-11): the two cases
    // where fidelity must yield.
    let redacted = !redaction_map.is_empty() || hooks_rewrote;
    let original_model = model.clone();
    let outbound_for = |target: &str| -> Option<Bytes> {
        if !redacted && !rerouted && target == original_model {
            return Some(body.clone());
        }
        let mut v = json_body.clone();
        v["model"] = Value::String(target.to_owned());
        serde_json::to_vec(&v).ok().map(Bytes::from)
    };
    let routed = route_plan.as_ref().is_some_and(|p| p.dispatches()) || pooled;
    let mut ledger: Vec<tracelane_shared::DispatchAttempt> = route_plan
        .as_deref()
        .map_or_else(Vec::new, crate::routing::RoutePlan::skipped_attempts);
    let outcome = crate::routing::relay::run(
        &state,
        crate::routing::relay::RelayPlan {
            attempt_security: &attempt_security,
            entitlements: entitlements.as_deref(),
            request_start,
            tenant_id,
            provider_id: PROVIDER_ID,
            family: PROVIDER_ID,
            region: &region,
            targets: &targets,
            pooled,
            fallthrough: Messages::ROUTING.fallthrough,
            max_attempts: if routed {
                crate::routing::limits().max_attempts
            } else {
                1
            },
        },
        first_key,
        &mut key_cursor,
        &mut ledger,
        |ti, key| {
            let outbound = outbound_for(&targets[ti]);
            let state = &state;
            let headers = &headers;
            async move {
                let outbound =
                    outbound.ok_or_else(|| anyhow::anyhow!("the request could not be prepared"))?;
                forward(state, headers, &outbound, key.expose_secret(), false).await
            }
        },
    )
    .await;
    dispatch_guard.record_attempts(ledger.clone());
    let (upstream, provider_key) = match outcome {
        crate::routing::relay::RelayOutcome::Served {
            upstream,
            target,
            label,
            key,
        } => {
            model.clone_from(&targets[target]);
            if let Some(p) = route_plan.as_deref().filter(|p| p.dispatches()) {
                identity.route.target_index = p.candidates.get(target).map(|c| c.target_index);
            }
            if pooled {
                identity.route.key_label = Some(label);
            }
            dispatch_guard.record_route(identity.route.clone());
            (upstream, key)
        }
        crate::routing::relay::RelayOutcome::Refused(denied) => {
            dispatch_guard.abort(denied.code(), None);
            return Messages::refuse(denied.0);
        }
        crate::routing::relay::RelayOutcome::BreakerOpen => {
            tracing::warn!(
                provider = PROVIDER_ID,
                "upstream unavailable (circuit open) — short-circuiting with 503"
            );
            dispatch_guard.abort("upstream_circuit_open", None);
            return overloaded_response();
        }
        crate::routing::relay::RelayOutcome::Timeout(timeout) => {
            dispatch_guard.abort("upstream_timeout", None);
            return timeout.response();
        }
        crate::routing::relay::RelayOutcome::Transport => {
            tracing::warn!(provider = PROVIDER_ID, "messages dispatch failed");
            crate::otlp_emit::emit_operation_exception(
                tenant_id,
                PROVIDER_ID,
                &region,
                "dispatch_failed",
                None,
            );
            dispatch_guard.abort("provider_unavailable", None);
            return coded_error(
                StatusCode::BAD_GATEWAY,
                "provider_unavailable",
                "Anthropic did not serve this request",
            );
        }
        crate::routing::relay::RelayOutcome::Status { upstream, key } => {
            let status = upstream.status().as_u16();
            let (our_status, code, message) = map_upstream_status(status);
            tracing::warn!(provider = PROVIDER_ID, status, code, "Anthropic API error");
            crate::otlp_emit::emit_operation_exception(
                tenant_id,
                PROVIDER_ID,
                &region,
                "dispatch_failed",
                Some(status),
            );
            // OG-10 D7: relay the provider's own status + body (scrubbed) and its retry
            // headers, except for the key-rejection statuses whose bodies echo the key.
            let resp = upstream_error_response(
                upstream,
                (our_status, code, message),
                correlation_id,
                key.expose_secret(),
            )
            .await;
            dispatch_guard.abort(code, None);
            return resp;
        }
    };
    let _ = &provider_key;

    // --- Step 6: Relay + span ---
    let span_ctx = SpanContext {
        tenant_id: tenant_id.clone(),
        trace_id,
        parent_span_id: inbound_parent,
        model: model.clone(),
        identity,
        request_start,
        dispatch_ts,
        api_key_id: claims.api_key_id().map(str::to_owned),
        captured_input,
        capture,
        // GWY-48: both wires use the converted ChatRequest for request settings.
        // This keeps gen_ai_request_temperature comparable across routes.
        // The capture decision above governs input and output together.
        // The original Anthropic body remains the upstream source.
        request_config: {
            let rc = crate::server::RequestConfig::build(&chat_request).with_policy_flags();
            match &zdr_eligible {
                Some(eligible) => rc.with_zdr(eligible.clone()),
                None => rc,
            }
        },
        aft_id: warn_aft_id,
        // OG-11: the attempts of a routed request (pool keys, targets); empty otherwise.
        dispatch_attempts: ledger,
    };
    let response_inputs = crate::guardrail::ResponseInputs {
        hooks: Some(request_hooks.clone()),
        hook_events: span_ctx.identity.hook_events.clone(),
        tenant_id: tenant_id.clone(),
        api_key_id: claims.api_key_id().map(str::to_owned),
        project_id: claims.governance.as_ref().and_then(|g| g.project_id),
        correlation_id,
        system_prompt: chat_request.system.clone(),
        model: model.clone(),
        session: crate::guardrail::SessionState::fresh(conversation_id),
        actor: claims.sub.clone(),
        // Anthropic Messages has no `response_format`, so R5 is not applicable —
        // stating that here rather than letting `extract_expected_format` read an
        // OpenAI field off a body that never carries one.
        expected_format: json_body.pointer("/output_config/format").and_then(|f| {
            (f.get("type").and_then(Value::as_str) == Some("json_schema")).then(|| {
                crate::guardrail::context::ExpectedFormat {
                    json: true,
                    schema: f.get("schema").cloned(),
                }
            })
        }),
    };
    let guard = crate::guardrail::ResponseGuard::new(
        state.guardrail.clone(),
        response_inputs,
        redaction_map,
    );

    if is_streaming(&json_body) {
        // The relay owns the record from here — its `RelayFinalizer` finishes
        // the span on every termination path INCLUDING a client hang-up (B-375
        // c). The dispatch guard is handed INTO the generator and disarmed once
        // the finalizer exists (security review M-4): a hang-up before hyper's
        // first poll of the body is then recorded by the guard, not by nothing.
        stream_response(
            state,
            upstream,
            guard,
            span_ctx,
            correlation_id,
            Some(dispatch_guard),
        )
    } else {
        let resp = buffered_response(state, upstream, guard, span_ctx, correlation_id).await;
        // The buffered path recorded its span inside `buffered_response`; a
        // client that hung up DURING that await dropped this future above this
        // line, and the guard's `Drop` recorded the cancellation instead.
        dispatch_guard.disarm();
        resp
    }
}

/// The 503 every "Anthropic is not reachable through this gateway" exit renders.
fn overloaded_response() -> Response {
    let mut resp = anthropic_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "overloaded_error",
        "Anthropic is temporarily unavailable through this gateway",
        &[
            ("code", json!("upstream_circuit_open")),
            ("provider", json!(PROVIDER_ID)),
        ],
    );
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("10"),
    );
    resp
}

/// Both budget refusals in one shape. **402, not 429** — a 429 says "retry later"
/// and every SDK will; a budget ceiling is a hard stop no retry resolves.
fn budget_error(code: &str, budget_usd: f64, spent_usd: f64) -> Response {
    anthropic_error(
        StatusCode::PAYMENT_REQUIRED,
        "invalid_request_error",
        "this credential has reached its monthly budget",
        &[
            ("code", json!(code)),
            ("budget_usd", json!(budget_usd)),
            ("spent_usd", json!(spent_usd)),
            ("resets_at", json!(crate::server::next_month_boundary_iso())),
        ],
    )
}

// `header_str` (a `HeaderMap` -> `Option<String>` lookup helper) was deleted
// 2026-09-12 (B-390) — zero callers anywhere in the tree.

/// POST the (possibly redacted) body to Anthropic with the tenant's BYOK key.
///
/// SSRF: `validate_url` before the call, `safe_client_builder` for the client.
/// `count_tokens` shares this so the two paths cannot resolve different origins.
///
/// # Errors
/// **Fail-CLOSED.** `Err` on an SSRF refusal, a client-build failure, or a transport
/// failure reaching Anthropic. A non-2xx from Anthropic is `Ok` — the caller inspects
/// the status and maps it, because those need different answers to the customer (a
/// rejected key vs an outage) and the upstream BODY must be dropped in every case.
async fn forward(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    api_key: &str,
    count_tokens: bool,
) -> anyhow::Result<reqwest::Response> {
    let base = state.providers.anthropic.base_url().trim_end_matches('/');
    let url = if count_tokens {
        format!("{base}/v1/messages/count_tokens")
    } else {
        format!("{base}/v1/messages")
    };
    crate::ssrf_guard::validate_url(&url).await?;
    let req = upstream_client()?
        .post(&url)
        .header("x-api-key", api_key)
        .header("content-type", "application/json")
        .body(body.clone());
    // OG-02 D6 sweep: a `reqwest::Error` prints its URL; strip it before it becomes an
    // `anyhow` chain that something logs.
    crate::routing::deadlines::send(passthrough_version_headers(headers, req)).await
}

// ── Upstream error relay (OG-10 §3.1 / D7) ───────────────────────────────────

/// The most of an upstream error body this route will hold and relay.
const RELAY_ERROR_BODY_CAP: usize = 64 * 1024;

/// Upstream response headers forwarded on a relayed error: exactly these, never a
/// blanket copy. `retry-after` is handled separately (normalised to integer seconds).
fn forwarded_error_header(name: &str) -> bool {
    matches!(name, "x-should-retry" | "request-id")
        || name.starts_with("anthropic-ratelimit-unified-")
}

/// Read at most [`RELAY_ERROR_BODY_CAP`] bytes of an error body. The `bool` is `true`
/// when the body was longer (or the read failed part-way), i.e. what is returned is
/// NOT the whole body and must not be relayed as one.
async fn read_error_body_capped(
    upstream: reqwest::Response,
) -> Result<(Vec<u8>, bool), crate::routing::deadlines::Timeout> {
    use futures::StreamExt as _;
    let mut stream = upstream.bytes_stream();
    let mut out: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                if let Some(timeout) = crate::routing::deadlines::Timeout::find(&err) {
                    return Err(timeout);
                }
                return Ok((out, true));
            }
        };
        if out.len() + chunk.len() > RELAY_ERROR_BODY_CAP {
            return Ok((out, true));
        }
        out.extend_from_slice(&chunk);
    }
    Ok((out, false))
}

/// The client response for a non-2xx upstream status.
///
/// **Relayed with the provider's own status and body** — Claude Code's context-overflow
/// recovery matches on Anthropic's wording and its retry logic on the status and
/// `retry-after` (`code.claude.com/docs/en/llm-gateway-protocol`: "forward upstream error
/// bodies unmodified") — **except**:
/// - `mapped` says the status is a key rejection (401/403/407): the body can echo
///   `x-api-key`, so the response is our own `provider_key_rejected` and the body is dropped;
/// - the body is not JSON, or was longer than [`RELAY_ERROR_BODY_CAP`], or did not stay JSON
///   after scrubbing: the ORIGINAL status survives in an Anthropic-shaped error of ours, so
///   the client still sees the right class and never a truncated or foreign body.
///
/// Before relaying, the body has the tenant's own key removed verbatim and goes through
/// `tracelane_shared::redact::scrub`. Our `correlation_id` is added as the
/// `x-tracelane-correlation-id` HEADER — never injected into the body, so the bytes stay
/// the provider's.
///
/// Fail-CLOSED on the leak question: anything uncertain is answered with our own body.
async fn upstream_error_response(
    upstream: reqwest::Response,
    mapped: (StatusCode, &'static str, &'static str),
    correlation_id: ulid::Ulid,
    api_key: &str,
) -> Response {
    let (our_status, code, message) = mapped;
    let status = upstream.status().as_u16();
    let headers = upstream.headers().clone();
    let key_rejected = matches!(status, 401 | 403 | 407);
    let relayable = (400..600).contains(&status) && !key_rejected;

    let mut resp = if relayable {
        let (body, truncated) = match read_error_body_capped(upstream).await {
            Ok(body) => body,
            Err(timeout) => return timeout.response(),
        };
        let text = String::from_utf8_lossy(&body);
        let text = if api_key.is_empty() {
            text.into_owned()
        } else {
            text.replace(api_key, "[REDACTED]")
        };
        let scrubbed = tracelane_shared::redact::scrub(text.as_bytes());
        let relayed_status = StatusCode::from_u16(status).unwrap_or(our_status);
        if !truncated && serde_json::from_slice::<Value>(&scrubbed).is_ok() {
            let mut r = (relayed_status, scrubbed).into_response();
            r.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
            r
        } else {
            anthropic_error(
                relayed_status,
                error_type_for(relayed_status),
                "the provider returned an error whose body could not be relayed as JSON",
                &[
                    ("code", json!("provider_error_not_relayable")),
                    ("upstream_status", json!(status)),
                ],
            )
        }
    } else {
        // Discard without waiting for a body that may echo the key.
        drop(upstream);
        coded_error(our_status, code, message)
    };

    for (name, value) in &headers {
        if forwarded_error_header(name.as_str()) {
            resp.headers_mut().insert(name.clone(), value.clone());
        }
    }
    // Normalised: delta-seconds or an HTTP-date in, whole seconds out, clamped by the
    // reference table. Garbage is dropped rather than forwarded.
    if relayable && let Some(wait) = crate::providers::retry_after_from(&headers) {
        let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&correlation_id.to_string()) {
        resp.headers_mut().insert("x-tracelane-correlation-id", v);
    }
    resp
}

// ── Span plumbing ────────────────────────────────────────────────────────────

/// Everything the completion span needs, carried across the `'static` stream
/// boundary. Owned because an SSE body outlives the handler frame.
pub(crate) struct SpanContext {
    pub(crate) tenant_id: TenantId,
    pub(crate) trace_id: Uuid,
    pub(crate) parent_span_id: Option<Uuid>,
    pub(crate) model: String,
    // `conversation_id: Option<String>` (deleted 2026-09-12, B-390) — never
    // read after construction; the span builder below reads
    // `ctx.identity.conversation_id` instead (`CallerIdentity` already
    // carries its own copy, `server.rs:4142`), so this was a redundant
    // duplicate, not the real source.
    pub(crate) identity: crate::server::CallerIdentity,
    pub(crate) request_start: chrono::DateTime<chrono::Utc>,
    pub(crate) dispatch_ts: chrono::DateTime<chrono::Utc>,
    pub(crate) api_key_id: Option<String>,
    pub(crate) captured_input: Option<CapturedInput>,
    pub(crate) capture: crate::server::config::ContentCapture,
    pub(crate) request_config: crate::server::RequestConfig,
    pub(crate) aft_id: Option<&'static str>,
    /// `OG-11`: the attempt ledger of a routed request; empty = absent on the span.
    pub(crate) dispatch_attempts: Vec<tracelane_shared::DispatchAttempt>,
}

/// Build and publish the completion span, meter the tokens, record the spend.
///
/// Exactly the shape `chat_completions_handler` publishes — same builder, same
/// attribute set, same `pricing::cost_usd` fallback — so an Anthropic-wire request
/// is one row in `/traces` beside a chat/completions one, not a second dialect.
/// Fail-OPEN throughout: this runs after the client already has its answer.
/// How a relayed request ended — the half of the span `finish_span` cannot read
/// off the context: whether it streamed, when the provider finished, and why it
/// stopped (`error_reason`), including the one reason only a `Drop` can know.
pub(crate) struct FinishOutcome<'a> {
    pub(crate) tool_calls: Option<&'a crate::server::ToolCallAccumulator>,
    pub(crate) output_tool_calls: Option<&'a crate::server::ToolCallAccumulator>,
    pub(crate) output_text: Option<&'a str>,
    pub(crate) served: crate::server::ServedMeta,
    pub(crate) finish_reason: Option<crate::providers::FinishReason>,
    pub(crate) stream: bool,
    pub(crate) ttft_us: Option<u32>,
    pub(crate) provider_complete_ts: chrono::DateTime<chrono::Utc>,
    pub(crate) error_reason: Option<&'a str>,
    /// B-375 (c): the client hung up mid-stream; the span says so.
    pub(crate) cancelled: bool,
}

pub(crate) fn finish_span(
    state: &AppState,
    ctx: SpanContext,
    usage: UsageAcc,
    outcome: FinishOutcome<'_>,
) {
    let FinishOutcome {
        tool_calls,
        output_tool_calls,
        output_text,
        served,
        finish_reason,
        stream,
        ttft_us,
        provider_complete_ts,
        error_reason,
        cancelled,
    } = outcome;
    let mut span = crate::server::build_gateway_span(
        &ctx.tenant_id,
        ctx.trace_id,
        ctx.parent_span_id,
        &ctx.model,
        &ctx.identity,
        ctx.request_start,
        usage.input,
        usage.output,
        ctx.aft_id,
        SpanUsageMeta {
            cache_read_input_tokens: usage.cache_read,
            cache_creation_input_tokens: usage.cache_creation,
            stream,
            // `None` on purpose: Anthropic puts no cost on the wire, so
            // `build_gateway_span` derives it from `pricing::cost_usd`. An unknown
            // model yields `None`, never a fabricated zero (ADR-055).
            cost_usd: None,
            served,
            finish_reason,
            // RI-05: no retry loop and no cross-provider failover on this route; OG-11
            // adds pool keys and same-provider targets, whose attempts ride here.
            dispatch_attempts: ctx.dispatch_attempts.clone(),
            // RI-05 / M11: Anthropic has no reasoning-token field on the wire.
            reasoning_output_tokens: None,
        },
        // No failover on this route, so never a failover attribution.
        None,
        Some(GatewayTiming {
            dispatch_ts: ctx.dispatch_ts,
            provider_complete_ts,
            ttft_us,
        }),
        error_reason,
        ctx.api_key_id.as_deref(),
    );
    if let Some(calls) = tool_calls {
        span.attributes.tracelane_response_tool_names = calls.response_tool_names();
        span.attributes.tracelane_response_tool_arg_bytes = calls.response_tool_arg_bytes();
        span.attributes.tracelane_response_tool_arg_fps =
            calls.response_tool_arg_fps(&ctx.tenant_id);
    }
    if let Some(captured) = ctx.captured_input {
        captured.apply(&mut span.attributes);
    }
    if error_reason != Some("guardrail_block")
        && let Some(output) = crate::server::CapturedOutput::build(
            ctx.capture,
            output_text.unwrap_or_default(),
            &output_tool_calls.map_or_else(Vec::new, |calls| calls.for_span()),
        )
    {
        output.apply(&mut span.attributes);
    }
    // GWY-48: unconditional — there is no content here to gate.
    ctx.request_config.apply(&mut span.attributes);
    if cancelled {
        // B-375 (c): the client went away mid-stream. Same attribute and counter
        // as the OpenAI SSE path's `StreamFinalizer`, so one query finds both.
        span.attributes.extra.insert(
            "tracelane.stream.cancelled".to_string(),
            serde_json::Value::Bool(true),
        );
        crate::server::STREAMS_FINALIZED_ON_DROP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    // Test seam: `spawn_span_publish` records into `otlp_emit::test_sink` before
    // its NATS branch, so a test asserting "the span carries the usage" is
    // asserting something even without NATS (`CLAUDE.md` §1).
    crate::server::record_key_spend(ctx.api_key_id.as_deref(), &span);
    crate::server::spawn_span_publish(state, span);
}

/// Test-only span sink — the crate-wide one (`otlp_emit::test_sink`, B-385
/// 2c), which absorbed this module's private copy. `spawn_span_publish` records
/// into it before the NATS branch, so `finish_span` no longer records here.
#[cfg(test)]
use crate::otlp_emit::test_sink as span_capture;

/// B-375 (c): the streaming relay's record, finished exactly once — by the
/// generator's tail on a clean end / transport error / guardrail block, or by
/// `Drop` when hyper discards the generator because the client hung up. The
/// span then carries the usage seen so far and `tracelane.stream.cancelled`,
/// the same shape `server::StreamFinalizer` gives the OpenAI SSE path.
pub(crate) struct RelayFinalizer {
    pub(crate) tool_calls: crate::server::ToolCallAccumulator,
    pub(crate) delivered_tool_calls: crate::server::ToolCallAccumulator,
    pub(crate) output_ring: Option<String>,
    pub(crate) output_cap: usize,
    pub(crate) served: crate::server::ServedMeta,
    pub(crate) finish_reason: Option<crate::providers::FinishReason>,
    pub(crate) state: AppState,
    pub(crate) ctx: Option<SpanContext>,
    pub(crate) usage: UsageAcc,
    pub(crate) first_byte_ts: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) error_reason: Option<&'static str>,
    pub(crate) finished: bool,
}

impl RelayFinalizer {
    fn observe_metadata(&mut self, frame: &Bytes) {
        let Some(v) = frame_data(frame).and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
            return;
        };
        match v["type"].as_str() {
            Some("message_start") => self.served.absorb(
                v["message"]["id"].as_str().map(str::to_owned),
                v["message"]["model"].as_str().map(str::to_owned),
                None,
            ),
            Some("message_delta") => {
                self.finish_reason = v["delta"]["stop_reason"]
                    .as_str()
                    .and_then(crate::providers::FinishReason::from_anthropic_stop_reason);
            }
            _ => {}
        }
    }

    fn record_delivered(&mut self, frame: &Bytes) {
        let Some(v) = frame_data(frame).and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
            return;
        };
        self.delivered_tool_calls.absorb_anthropic(&v);
        let text = match v["type"].as_str() {
            Some("content_block_start") if v["content_block"]["type"] == "text" => {
                v["content_block"]["text"].as_str()
            }
            Some("content_block_delta") if v["delta"]["type"] == "text_delta" => {
                v["delta"]["text"].as_str()
            }
            _ => None,
        };
        if let (Some(buf), Some(text)) = (&mut self.output_ring, text) {
            crate::server::ring_push(buf, text, self.output_cap);
        }
    }

    pub(crate) fn finish(&mut self, cancelled: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        let Some(ctx) = self.ctx.take() else {
            return;
        };
        let ttft_us = self.first_byte_ts.and_then(|t| {
            (t - ctx.dispatch_ts)
                .num_microseconds()
                .and_then(|us| u32::try_from(us.max(0)).ok())
        });
        let reason = if cancelled {
            Some("client_cancelled")
        } else {
            self.error_reason
        };
        finish_span(
            &self.state,
            ctx,
            std::mem::take(&mut self.usage),
            FinishOutcome {
                tool_calls: Some(&self.tool_calls),
                output_tool_calls: Some(&self.delivered_tool_calls),
                output_text: self.output_ring.as_deref(),
                served: std::mem::take(&mut self.served),
                finish_reason: self.finish_reason,
                stream: true,
                ttft_us,
                provider_complete_ts: chrono::Utc::now(),
                error_reason: reason,
                cancelled,
            },
        );
    }
}

impl Drop for RelayFinalizer {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(true);
        }
    }
}

// ── Streaming relay ──────────────────────────────────────────────────────────

/// Relay the provider's SSE back to the client through the response seam.
///
/// The response is an `axum::body::Body` over raw [`Bytes`], NOT `axum::Sse`: an
/// `Sse` would re-frame each event from our own `Event` builder, which is
/// re-serialisation by another name. Byte fidelity is only meaningful if the bytes
/// are never rebuilt.
fn stream_response(
    state: AppState,
    upstream: reqwest::Response,
    guard: crate::guardrail::ResponseGuard,
    ctx: SpanContext,
    correlation_id: ulid::Ulid,
    handover: Option<crate::server::DispatchGuard>,
) -> Response {
    use futures::StreamExt as _;

    let correlation = correlation_id.to_string();
    let body = async_stream::stream! {
        let mut bytes = upstream.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        let mut relay = Relay::new(guard);
        // B-375 (c): the record is OWNED by a Drop guard from the first byte.
        // hyper drops this generator the moment the client hangs up, and a
        // `finish_span` after the loop never runs for that request; the
        // finalizer's `Drop` records what was seen so far with
        // `tracelane.stream.cancelled = true` instead. Every counter the tail
        // used to keep as a local lives on it.
        let tenant_for_exception = ctx.tenant_id.clone();
        let capture = ctx.capture;
        let mut fin = RelayFinalizer {
            tool_calls: crate::server::ToolCallAccumulator::default(),
            delivered_tool_calls: crate::server::ToolCallAccumulator::default(),
            output_ring: capture.output.then(String::new),
            output_cap: capture.max_field_bytes,
            served: crate::server::ServedMeta::default(),
            finish_reason: None,
            state: state.clone(),
            ctx: Some(ctx),
            usage: UsageAcc::default(),
            first_byte_ts: None,
            error_reason: None,
            finished: false,
        };
        // The finalizer exists: the dispatch guard's job is done.
        if let Some(mut dispatch_guard) = handover {
            dispatch_guard.disarm();
        }
        let mut blocked = false;

        'outer: loop {
            let chunk = match bytes.next().await {
                Some(Ok(c)) => c,
                Some(Err(err)) => {
                    if let Some(timeout) = crate::routing::deadlines::Timeout::find(&err) {
                        fin.error_reason = Some("upstream_timeout");
                        if let Some(ctx) = &mut fin.ctx { timeout.record_attempt(&mut ctx.dispatch_attempts); }
                        yield Ok(timeout.event("messages"));
                        blocked = true;
                        break 'outer;
                    }
                    // A transport-level failure mid-response. Record it so the span
                    // carries status Error — a mid-stream failure that reads as a
                    // success is how an error-rate metric pins itself at 0%.
                    tracing::warn!(error = %err.without_url(), "Anthropic SSE stream error");
                    fin.error_reason = Some("provider_stream_error");
                    crate::otlp_emit::emit_operation_exception(
                        &tenant_for_exception,
                        PROVIDER_ID,
                        "default",
                        "provider_stream_error",
                        None,
                    );
                    break 'outer;
                }
                None => break 'outer,
            };
            if fin.first_byte_ts.is_none() {
                fin.first_byte_ts = Some(chrono::Utc::now());
            }
            buf.extend_from_slice(&chunk);

            while let Some(raw) = split_frame(&mut buf) {
                fin.observe_metadata(&raw);
                if let Some(value) = frame_data(&raw).and_then(|data| serde_json::from_str(data).ok()) {
                    fin.tool_calls.absorb_anthropic(&value);
                }
                let frame = classify_frame(raw, &mut fin.usage, &mut fin.error_reason);
                match relay.push(frame, fin.usage.as_usage()).await {
                    Release::Bytes(out) => {
                        for b in out {
                            fin.record_delivered(&b);
                            yield Ok::<Bytes, std::convert::Infallible>(b);
                        }
                    }
                    Release::Blocked(out, reason) => {
                        for b in out {
                            yield Ok(b);
                        }
                        yield Ok(synth_block_error(reason, &correlation));
                        blocked = true;
                        fin.error_reason = Some("guardrail_block");
                        break 'outer;
                    }
                }
            }
        }

        // A trailing frame with no blank-line terminator (a truncated response).
        if !blocked && !buf.is_empty() {
            let raw = Bytes::from(std::mem::take(&mut buf));
            fin.observe_metadata(&raw);
            let frame = classify_frame(raw, &mut fin.usage, &mut fin.error_reason);
            if let Release::Bytes(out) = relay.push(frame, fin.usage.as_usage()).await {
                for b in out {
                    fin.record_delivered(&b);
                    yield Ok(b);
                }
            }
        }

        if !blocked {
            match relay.finish(fin.usage.as_usage()).await {
                Release::Bytes(out) => {
                    for b in out {
                        fin.record_delivered(&b);
                        yield Ok(b);
                    }
                }
                Release::Blocked(_, reason) => {
                    yield Ok(synth_block_error(reason, &correlation));
                    fin.error_reason = Some("guardrail_block");
                }
            }
        }

        // AFTER the loop, on EVERY termination path — a clean end, a mid-stream
        // transport error, and a guardrail block all land here. The chat path's
        // span-publish ordering invariant, for the same reason: a blocked or
        // truncated response that produces no span is a request the ledger attests
        // to and `/traces` cannot show. A client hang-up never reaches this line;
        // `RelayFinalizer::drop` records that one.
        fin.finish(false);
    };

    let mut resp = Response::new(Body::from_stream(body));
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/event-stream"),
    );
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    resp
}

/// Read one raw SSE frame: fold any usage it carries, note a provider `error`
/// event, and mark it as a text delta if that is what it is.
fn classify_frame(
    raw: Bytes,
    usage: &mut UsageAcc,
    error_reason: &mut Option<&'static str>,
) -> Frame {
    let Some(data) = frame_data(&raw) else {
        return Frame {
            raw,
            text: None,
            index: 0,
        };
    };
    let Ok(v) = serde_json::from_str::<Value>(data) else {
        return Frame {
            raw,
            text: None,
            index: 0,
        };
    };
    let index = v.get("index").and_then(Value::as_u64).unwrap_or(0);
    match v.get("type").and_then(Value::as_str) {
        // `message_start` carries input + cache tokens; `message_delta` carries the
        // final output count. MAX-merged (B-104) rather than summed.
        Some("message_start") => {
            if let Some(u) = v.pointer("/message/usage") {
                usage.merge(u);
            }
        }
        Some("message_delta") => {
            if let Some(u) = v.get("usage") {
                usage.merge(u);
            }
        }
        Some("error") => {
            // Anthropic ended the response with its own error event. It is the
            // provider's frame and is relayed verbatim; the span must not call it a
            // success.
            *error_reason = Some("provider_stream_error");
        }
        Some("content_block_delta")
            if v.pointer("/delta/type").and_then(Value::as_str) == Some("text_delta") =>
        {
            let text = v
                .pointer("/delta/text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            return Frame {
                raw,
                text: Some(text),
                index,
            };
        }
        _ => {}
    }
    Frame {
        raw,
        text: None,
        index,
    }
}

// ── Buffered (non-streaming) response ────────────────────────────────────────

/// Return the provider's JSON verbatim, after the response seam has cleared it.
async fn buffered_response(
    state: AppState,
    upstream: reqwest::Response,
    mut guard: crate::guardrail::ResponseGuard,
    ctx: SpanContext,
    correlation_id: ulid::Ulid,
) -> Response {
    let raw = match upstream.bytes().await {
        Ok(b) => b,
        Err(err) => {
            let timeout = crate::routing::deadlines::Timeout::find(&err);
            let mut ctx = ctx;
            if let Some(t) = timeout {
                t.record_attempt(&mut ctx.dispatch_attempts);
            }
            tracing::warn!(error = %err.without_url(), "reading the Anthropic response body failed");
            finish_span(
                &state,
                ctx,
                UsageAcc::default(),
                FinishOutcome {
                    tool_calls: None,
                    output_tool_calls: None,
                    output_text: None,
                    served: crate::server::ServedMeta::default(),
                    finish_reason: None,
                    stream: false,
                    ttft_us: None,
                    provider_complete_ts: chrono::Utc::now(),
                    error_reason: Some(if timeout.is_some() {
                        "upstream_timeout"
                    } else {
                        "provider_stream_error"
                    }),
                    cancelled: false,
                },
            );
            if let Some(t) = timeout {
                return t.response();
            }
            return coded_error(
                StatusCode::BAD_GATEWAY,
                "provider_unavailable",
                "Anthropic did not serve this request",
            );
        }
    };
    let provider_complete_ts = chrono::Utc::now();

    let parsed: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    let mut served = crate::server::ServedMeta::default();
    served.absorb(
        parsed["id"].as_str().map(str::to_owned),
        parsed["model"].as_str().map(str::to_owned),
        None,
    );
    let finish_reason = parsed["stop_reason"]
        .as_str()
        .and_then(crate::providers::FinishReason::from_anthropic_stop_reason);
    let mut tool_calls = crate::server::ToolCallAccumulator::default();
    tool_calls.absorb_anthropic(&parsed);
    let mut usage = UsageAcc::default();
    if let Some(u) = parsed.get("usage") {
        usage.merge(u);
    }

    // Every text block, in order — what the response rails read.
    let text: String = parsed
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .concat()
        })
        .unwrap_or_default();

    let mut safe = String::new();
    let mut blocked = if parsed.get("content").and_then(Value::as_array).is_none()
        || crate::guardrail::streaming::has_unscanned_output(&parsed)
    {
        guard.refuse_unscanned_output().await
    } else {
        None
    };
    if blocked.is_none() && !text.is_empty() {
        match guard.on_delta(&text, Some(&usage.as_usage())).await {
            crate::guardrail::GuardStep::Emit(s) => safe.push_str(&s),
            crate::guardrail::GuardStep::Block { reason_code } => blocked = Some(reason_code),
        }
    }
    if blocked.is_none() {
        match guard.on_end(Some(&usage.as_usage())).await {
            crate::guardrail::GuardStep::Emit(s) => safe.push_str(&s),
            crate::guardrail::GuardStep::Block { reason_code } => blocked = Some(reason_code),
        }
    }

    // The span is published BEFORE the block short-circuits, on every path — a
    // content-filtered response that drops its span is the #81 regression.
    finish_span(
        &state,
        ctx,
        usage,
        FinishOutcome {
            tool_calls: Some(&tool_calls),
            output_tool_calls: Some(&tool_calls),
            output_text: (blocked.is_none()).then_some(safe.as_str()),
            served,
            finish_reason,
            stream: false,
            ttft_us: None,
            provider_complete_ts,
            error_reason: blocked.map(|_| "guardrail_block"),
            cancelled: false,
        },
    );

    if let Some(reason) = blocked {
        return anthropic_error(
            StatusCode::FORBIDDEN,
            "permission_error",
            "response blocked by Tracelane inline guardrail",
            &[
                ("code", json!("guardrail_block")),
                ("reason_code", json!(reason)),
                ("correlation_id", json!(correlation_id.to_string())),
            ],
        );
    }

    let out: Bytes = if safe == text {
        raw // byte-identical — the whole point
    } else {
        // A rail redacted. There is no length-preserving mapping from the
        // transformed text back onto the individual blocks it came from, so the
        // safe text lands in the FIRST text block and later text blocks are
        // emptied; `tool_use` and `thinking` blocks are untouched, so tool calling
        // still works. Shape-preserving and unredacted-text-free, in that order.
        match rebuild_with_text(&parsed, &safe) {
            Some(v) => Bytes::from(v),
            None => {
                return coded_error(
                    StatusCode::BAD_GATEWAY,
                    "provider_unavailable",
                    "the provider response could not be prepared",
                );
            }
        }
    };
    let mut resp = (StatusCode::OK, out).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp
}

/// Replace the response's text content with `safe`, keeping every other block.
fn rebuild_with_text(parsed: &Value, safe: &str) -> Option<Vec<u8>> {
    let mut out = parsed.clone();
    let blocks = out.get_mut("content")?.as_array_mut()?;
    let mut first = true;
    for b in blocks.iter_mut() {
        if b.get("type").and_then(Value::as_str) != Some("text") {
            continue;
        }
        if let Some(t) = b.get_mut("text") {
            *t = Value::String(if first {
                first = false;
                safe.to_owned()
            } else {
                String::new()
            });
        }
    }
    serde_json::to_vec(&out).ok()
}

// ── `POST /v1/messages/count_tokens` ─────────────────────────────────────────

/// Anthropic's pre-flight token count — auth + BYOK + forward.
///
/// **No span, no ledger row, no quota, no budget, and that is deliberate**: it is
/// not an inference. It produces no tokens, costs the tenant nothing at Anthropic,
/// and writing a ledger row for it would put an event in a tamper-evident export
/// that no customer asked to attest to. Auth and the `chat` scope still apply, and
/// so does the rate limiter — it uses the tenant's decrypted credential, and an
/// unauthenticated or unmetered credential path is a hole regardless of price.
///
/// # Errors
/// Fail-CLOSED on auth, scope, routing and BYOK; the upstream body is relayed
/// verbatim on success and dropped on failure (credential echo).
#[instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
pub async fn count_tokens_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match authenticate(&headers).await {
        Ok(claims) => count_tokens_with_claims(state, headers, body, claims).await,
        Err(resp) => resp,
    }
}

/// `count_tokens` from the scope gate down — split for the same reason
/// [`messages_with_claims`] is.
pub(crate) async fn count_tokens_with_claims(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    claims: crate::auth::Claims,
) -> Response {
    if let Some(refusal) = scope_refusal(&claims) {
        return refusal;
    }
    let tenant_id = &claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    // M-A: the strict parse — this body is forwarded as sent.
    let json_body = match crate::strict_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return coded_error(
                StatusCode::BAD_REQUEST,
                e.code(),
                &e.message("request body is not valid JSON"),
            );
        }
    };
    let Some(model) = json_body.get("model").and_then(Value::as_str) else {
        return coded_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "`model` is required",
        );
    };
    if crate::providers::ProviderRegistry::provider_id_for_model(model) != Some(PROVIDER_ID) {
        return coded_error(
            StatusCode::BAD_REQUEST,
            "unroutable_model",
            "POST /v1/messages/count_tokens serves Anthropic models only",
        );
    }

    let entitlements = match &state.entitlements {
        Some(cache) => Some(cache.resolved(*tenant_id.as_uuid()).await),
        None => None,
    };
    if let Some(response) = crate::routing::deadlines::invalid_document(entitlements.as_deref()) {
        return response;
    }
    // rev6: this forwards the caller's prompt with the tenant's key, so the pause, the
    // blocks and the workspace / key model-provider rules apply before anything leaves.
    if let Some(r) = crate::controls::companion_refusal(
        &claims,
        entitlements.as_deref().map(|e| &*e.controls),
        model,
        PROVIDER_ID,
    ) {
        let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::FORBIDDEN);
        return anthropic_error(
            status,
            error_type_for(status),
            &r.message,
            &[("code", json!(r.code))],
        );
    }
    let rpm = entitlements
        .as_ref()
        .map_or(state.no_control_plane_rate_limit_rpm, |e| e.rate_limit_rpm);
    if let RateLimitDecision::Throttle { retry_after_secs } =
        state
            .rate_limiter
            .check_scoped(tenant_id, rpm, claims.api_key_id(), claims.rate_limit_rpm)
    {
        // RI-05 slice 3 follow-up (2026-09-20): the aggregate span, like the three
        // admission sites — a refusal here was the last one counted but never recorded.
        state.rejection_metrics.record_admission_refusal(
            tenant_id,
            claims.api_key_id(),
            crate::rejection_metrics::RejectionReason::RateLimited,
            chrono::Utc::now(),
        );
        return anthropic_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "rate limit exceeded",
            &[
                ("code", json!("rate_limited")),
                ("retry_after_secs", json!(retry_after_secs)),
            ],
        );
    }

    // OG-11: count_tokens takes the first usable key of Anthropic's pool.
    let routing_state: std::sync::Arc<crate::routing::RoutingState> = entitlements
        .as_deref()
        .map(|e| std::sync::Arc::clone(&e.routing))
        .unwrap_or_default();
    let provider_key = match crate::routing::first_pool_key(
        &Messages::ROUTING,
        &routing_state,
        tenant_id,
        PROVIDER_ID,
    )
    .await
    .0
    {
        ProviderKey::Found(k) if !k.expose_secret().is_empty() => k,
        ProviderKey::KmsUnavailable => {
            return coded_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "kms_unavailable",
                "customer key service unavailable",
            );
        }
        ProviderKey::KmsDenied => {
            return coded_error(
                StatusCode::FORBIDDEN,
                "kms_access_denied",
                "customer key service refused access",
            );
        }
        ProviderKey::Unusable => {
            return coded_error(
                StatusCode::BAD_GATEWAY,
                "provider_key_unusable",
                "a stored Anthropic key could not be decrypted — rotate it in Settings → LLM providers",
            );
        }
        ProviderKey::LookupFailed => {
            return coded_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "provider_key_unavailable",
                "the key store could not be reached — nothing was sent to Anthropic; retry shortly",
            );
        }
        ProviderKey::Found(_) | ProviderKey::NotConfigured => {
            return coded_error(
                StatusCode::PAYMENT_REQUIRED,
                "provider_not_configured",
                "no Anthropic key stored for this workspace — add one in Settings → LLM providers, then retry",
            );
        }
    };

    // M-E (security re-review 2026-10-03): this forwards the WHOLE prompt, so R2 runs over
    // exactly what it forwards, the main route's way — redact in place, refuse what cannot be
    // rewritten. The original bytes go out unless R2 rewrote them.
    let deadlines = crate::routing::deadlines::Budget::for_request(
        entitlements.as_deref(),
        PROVIDER_ID,
        model,
        chrono::Utc::now(),
    );
    let mut json_body = json_body;
    let outbound: Bytes = match state
        .guardrail
        .companion_r2(
            tenant_id,
            claims.api_key_id(),
            claims.governance.as_ref().and_then(|g| g.project_id),
            &mut json_body,
        )
        .await
    {
        Ok(false) => body,
        Ok(true) => match serde_json::to_vec(&json_body) {
            Ok(v) => Bytes::from(v),
            Err(err) => {
                tracing::error!(error = %err, "redacted count_tokens body failed to serialise");
                return coded_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "the request could not be prepared for the provider",
                );
            }
        },
        Err(block) => {
            tracing::warn!(
                rail = block.rail,
                reason_code = block.reason_code,
                "count_tokens blocked by inline guardrail"
            );
            return anthropic_error(
                StatusCode::FORBIDDEN,
                "permission_error",
                "request blocked by Tracelane inline guardrail",
                &[
                    ("code", json!("guardrail_block")),
                    ("rail", json!(block.rail)),
                    ("reason_code", json!(block.reason_code)),
                ],
            );
        }
    };

    let upstream = match deadlines
        .scope(forward(
            &state,
            &headers,
            &outbound,
            provider_key.expose_secret(),
            true,
        ))
        .await
    {
        Ok(r) => r,
        Err(err) => {
            if let Some(timeout) = crate::routing::deadlines::Timeout::find(err.as_ref()) {
                return timeout.response();
            }
            tracing::warn!(error = %err, "count_tokens dispatch failed");
            return coded_error(
                StatusCode::BAD_GATEWAY,
                "provider_unavailable",
                "Anthropic did not serve this request",
            );
        }
    };
    let status = upstream.status();
    if !status.is_success() {
        // OG-10 D7: same rule as `/v1/messages` — 401/403/407 keep the key-rejected
        // mapping, everything else is the provider's own status and scrubbed body.
        return upstream_error_response(
            upstream,
            map_upstream_status(status.as_u16()),
            ulid::Ulid::new(),
            provider_key.expose_secret(),
        )
        .await;
    }
    match upstream.bytes().await {
        Ok(bytes) => {
            let mut resp = (StatusCode::OK, bytes).into_response();
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
            resp
        }
        Err(err) => {
            if let Some(timeout) = crate::routing::deadlines::Timeout::find(&err) {
                return timeout.response();
            }
            tracing::warn!(error = %err.without_url(), "reading the count_tokens response failed");
            coded_error(
                StatusCode::BAD_GATEWAY,
                "provider_unavailable",
                "Anthropic did not serve this request",
            )
        }
    }
}

/// The read model keeps an image marker, never its base64 payload. The original
/// Anthropic block is forwarded separately; CapturedInput caps this marker again.
fn capture_image_part(block: &Value) -> ContentPart {
    let source = &block["source"];
    let url = if source["type"] == "url" {
        let supplied = source["url"].as_str().unwrap_or_default();
        if supplied.starts_with("data:") {
            supplied
                .split_once(',')
                .map(|(prefix, _)| format!("{prefix},…[omitted]"))
                .unwrap_or_default()
        } else {
            supplied.to_owned()
        }
    } else {
        let media_type = source["media_type"]
            .as_str()
            .unwrap_or("application/octet-stream");
        format!("data:{media_type};base64,…[omitted]")
    };
    ContentPart::ImageUrl {
        image_url: tracelane_shared::ImageUrl { url, detail: None },
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// `GWY-47` — the route's own tests.
///
/// Gated on `debug_assertions` as well as `test`, exactly as
/// `server::embeddings_route_tests` is: wiremock binds `127.0.0.1` and the SSRF
/// guard blocks loopback in release, so these are debug-only by construction.
#[cfg(all(test, debug_assertions))]
mod tests {
    #[tokio::test]
    async fn og30_messages_and_count_tokens_honour_policy_before_upstream() {
        let _bypass = LoopbackBypassGuard::new();
        let upstream = MockServer::start().await;
        let t = tenant();
        install_byok(&t);
        let state = crate::guardrail::policy_tests::state(
            state_for(&upstream.uri(), in_memory_chain()),
            crate::guardrail::policy_tests::input_cap(),
        );
        let body = Bytes::from(
            json!({"model":"claude-sonnet-4-6","max_tokens":64,
            "messages":[{"role":"user","content":"a longer harmless request"}]})
            .to_string(),
        );
        let response = messages_with_claims(state, HeaderMap::new(), body, claims_for(&t)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let value = body_json(response).await;
        assert_eq!(value["error"]["reason_code"], "INPUT_TOKEN_CAP", "{value}");
        let state = crate::guardrail::policy_tests::state(
            state_for(&upstream.uri(), in_memory_chain()),
            json!({"rails":{"R2_secrets_pii":{"mode":"block"}}}),
        );
        let body = Bytes::from(
            json!({"model":"claude-sonnet-4-6",
            "messages":[{"role":"user","content":"person@example.com"}]})
            .to_string(),
        );
        let response =
            count_tokens_with_claims(state, HeaderMap::new(), body, claims_for(&t)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(upstream.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn og33_messages_and_count_tokens_honour_policy_before_upstream() {
        let _bypass = LoopbackBypassGuard::new();
        let upstream = MockServer::start().await;
        let t = tenant();
        install_byok(&t);
        let state = crate::guardrail::policy_tests::state(
            state_for(&upstream.uri(), in_memory_chain()),
            crate::guardrail::policy_tests::pii_block(),
        );
        let body = Bytes::from(
            json!({"model":"claude-sonnet-4-6","max_tokens":64,
            "messages":[{"role":"user","content":"person@example.com"}]})
            .to_string(),
        );
        let response = messages_with_claims(state, HeaderMap::new(), body, claims_for(&t)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let value = body_json(response).await;
        assert_eq!(value["error"]["reason_code"], "PII_EMAIL", "{value}");
        let state = crate::guardrail::policy_tests::state(
            state_for(&upstream.uri(), in_memory_chain()),
            json!({"rails":{"R2_secrets_pii":{"mode":"block"}}}),
        );
        let body = Bytes::from(
            json!({"model":"claude-sonnet-4-6",
            "messages":[{"role":"user","content":"person@example.com"}]})
            .to_string(),
        );
        let response =
            count_tokens_with_claims(state, HeaderMap::new(), body, claims_for(&t)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(upstream.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn og31_messages_and_count_tokens_honour_policy_before_upstream() {
        let _bypass = LoopbackBypassGuard::new();
        let upstream = MockServer::start().await;
        let t = tenant();
        install_byok(&t);
        let state = crate::guardrail::hook_tests::state(
            state_for(&upstream.uri(), in_memory_chain()),
            crate::guardrail::policy_tests::pii_block(),
        );
        let body = Bytes::from(
            json!({"model":"claude-sonnet-4-6","max_tokens":64,
            "messages":[{"role":"user","content":"person@example.com"}]})
            .to_string(),
        );
        let response = messages_with_claims(state, HeaderMap::new(), body, claims_for(&t)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let value = body_json(response).await;
        assert_eq!(value["error"]["reason_code"], "HOOK_DENY", "{value}");
        let state = crate::guardrail::hook_tests::state(
            state_for(&upstream.uri(), in_memory_chain()),
            json!({"rails":{"R2_secrets_pii":{"mode":"block"}}}),
        );
        let body = Bytes::from(
            json!({"model":"claude-sonnet-4-6",
            "messages":[{"role":"user","content":"person@example.com"}]})
            .to_string(),
        );
        let response =
            count_tokens_with_claims(state, HeaderMap::new(), body, claims_for(&t)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(upstream.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn og32_messages_and_count_tokens_honour_policy_before_upstream() {
        for hook in crate::guardrail::adapter_tests::fixtures() {
            let _bypass = LoopbackBypassGuard::new();
            let upstream = MockServer::start().await;
            let t = tenant();
            install_byok(&t);
            let state = crate::guardrail::hook_tests::state_with_hook(
                state_for(&upstream.uri(), in_memory_chain()),
                hook.clone(),
            );
            let body = Bytes::from(
                json!({"model":"claude-sonnet-4-6","max_tokens":64,
            "messages":[{"role":"user","content":"person@example.com"}]})
                .to_string(),
            );
            let response =
                messages_with_claims(state, HeaderMap::new(), body, claims_for(&t)).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let value = body_json(response).await;
            assert_eq!(value["error"]["reason_code"], "HOOK_DENY", "{value}");
            let state = crate::guardrail::hook_tests::state_with_hook(
                state_for(&upstream.uri(), in_memory_chain()),
                hook.clone(),
            );
            let body = Bytes::from(
                json!({"model":"claude-sonnet-4-6",
            "messages":[{"role":"user","content":"person@example.com"}]})
                .to_string(),
            );
            let response =
                count_tokens_with_claims(state, HeaderMap::new(), body, claims_for(&t)).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(upstream.received_requests().await.unwrap().is_empty());
        }
    }

    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tracelane_shared::api_scope::Scope;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Thread-local loopback opt-in — never a process-env mutation (that races
    /// the suite). Same guard shape as `providers::smoke_tests`.
    struct LoopbackBypassGuard;
    impl LoopbackBypassGuard {
        fn new() -> Self {
            crate::ssrf_guard::set_loopback_bypass_for_tests(true);
            Self
        }
    }
    impl Drop for LoopbackBypassGuard {
        fn drop(&mut self) {
            crate::ssrf_guard::set_loopback_bypass_for_tests(false);
        }
    }

    // ── The fixture ──────────────────────────────────────────────────────────

    /// A real-shaped Anthropic SSE response carrying a `thinking` block, two text
    /// deltas, a `tool_use` block with an `input_json_delta`, and usage split
    /// across `message_start` and `message_delta` — i.e. every element spec §7
    /// proof 5 names, in one stream.
    ///
    /// The `\r`-free `\n\n` framing is what Anthropic sends; the relay handles
    /// `\r\n\r\n` too, which `split_frame_handles_both_terminators` covers.
    const SSE_FIXTURE: &str = concat!(
        "event: message_start\n",
        r#"data: {"type":"message_start","message":{"id":"msg_01FIX","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"stop_reason":null,"usage":{"input_tokens":1234,"output_tokens":1,"cache_read_input_tokens":300,"cache_creation_input_tokens":12}}}"#,
        "\n\n",
        "event: content_block_start\n",
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#,
        "\n\n",
        "event: content_block_delta\n",
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"The user wants weather. I should call the tool."}}"#,
        "\n\n",
        "event: content_block_stop\n",
        r#"data: {"type":"content_block_stop","index":0}"#,
        "\n\n",
        "event: content_block_start\n",
        r#"data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}"#,
        "\n\n",
        "event: content_block_delta\n",
        r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Checking "}}"#,
        "\n\n",
        "event: content_block_delta\n",
        r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"the weather for you."}}"#,
        "\n\n",
        "event: content_block_stop\n",
        r#"data: {"type":"content_block_stop","index":1}"#,
        "\n\n",
        "event: content_block_start\n",
        r#"data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_01FIX","name":"get_weather","input":{}}}"#,
        "\n\n",
        "event: content_block_delta\n",
        r#"data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"Paris\"}"}}"#,
        "\n\n",
        "event: content_block_stop\n",
        r#"data: {"type":"content_block_stop","index":2}"#,
        "\n\n",
        "event: message_delta\n",
        r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":57}}"#,
        "\n\n",
        "event: message_stop\n",
        r#"data: {"type":"message_stop"}"#,
        "\n\n",
    );

    /// The non-streamed twin of the fixture — a `thinking` block, a text block and
    /// a `tool_use` block in one body.
    const JSON_FIXTURE: &str = r#"{"id":"msg_01FIXJ","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"thinking","thinking":"weather tool","signature":"sig"},{"type":"text","text":"Checking the weather for you."},{"type":"tool_use","id":"toolu_01FIXJ","name":"get_weather","input":{"city":"Paris"}}],"stop_reason":"tool_use","usage":{"input_tokens":1234,"output_tokens":57,"cache_read_input_tokens":300,"cache_creation_input_tokens":12}}"#;

    // ── Fixtures / helpers ───────────────────────────────────────────────────

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::new_v4())
    }

    /// `LegacyFullSurface` — what every JWT session and every pre-A13 key carries.
    fn claims_for(t: &TenantId) -> crate::auth::Claims {
        crate::auth::Claims {
            tenant_id: t.clone(),
            sub: format!("apikey:{}", Uuid::new_v4()),
            auth_method: crate::auth::AuthMethod::ApiKey,
            role: None,
            key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
            budget_reset: crate::spend::BudgetReset::Monthly,
            governance: None,
        }
    }

    /// A key scoped to exactly `scopes` — the shape A13 exists for.
    fn scoped_claims(t: &TenantId, scopes: &[Scope]) -> crate::auth::Claims {
        crate::auth::Claims {
            key_scope: crate::auth::scope::KeyScope::Scoped(
                scopes.iter().copied().collect::<BTreeSet<_>>(),
            ),
            ..claims_for(t)
        }
    }

    /// The OSS self-host shape: no Postgres, no ClickHouse, no NATS, no Polar.
    /// Entitlements `None` ⇒ the FREE tier, never a paid one
    /// (`.claude/rules/tenancy.md`).
    fn state_for(anthropic_base: &str, audit_chain: Arc<crate::audit::AuditChain>) -> AppState {
        let mut providers = crate::providers::ProviderRegistry::new().expect("registry");
        providers.anthropic = crate::providers::AnthropicProvider::for_base_url(anthropic_base)
            .expect("anthropic adapter for the mock");
        // B-385 (2c): the ONE harness state, with this route's own audit chain.
        crate::handler_harness::test_state_with_chain(providers, audit_chain)
    }

    fn in_memory_chain() -> Arc<crate::audit::AuditChain> {
        crate::handler_harness::in_memory_chain()
    }

    /// An audit chain whose Postgres control plane is unreachable, so
    /// `publish()` genuinely FAILS.
    ///
    /// Not a stub and not a flag: `AuditChain` with no pool takes the in-memory
    /// path and cannot error (`crates/gateway/CLAUDE.md`), so a fail-closed test
    /// built on the default chain would pass without ever observing the control
    /// block anything. Port 1 on loopback refuses instantly.
    fn unreachable_pg_chain() -> Arc<crate::audit::AuditChain> {
        let mut cfg = deadpool_postgres::Config::new();
        cfg.host = Some("127.0.0.1".to_owned());
        cfg.port = Some(1);
        cfg.user = Some("tracelane-unit-test-no-such-user".to_owned());
        cfg.dbname = Some("tracelane-unit-test-no-such-db".to_owned());
        cfg.connect_timeout = Some(std::time::Duration::from_millis(250));
        let pool = cfg
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .expect("deadpool builds without connecting");
        Arc::new(
            crate::audit::AuditChain::with_pg_pool(100, None, None, Some(pool))
                .expect("audit chain"),
        )
    }

    /// Store a decrypted Anthropic key on the hot-path BYOK cache — the same
    /// lookup `resolve_provider_key` consults first, so the real resolution path
    /// runs without a Postgres pool and without mutating process env.
    fn install_byok(t: &TenantId) {
        crate::db::provider_keys::cache_decrypted(
            t,
            PROVIDER_ID,
            Arc::new(secrecy::SecretString::from(
                "unit-test-anthropic-key-do-not-use-in-prod".to_owned(),
            )),
        );
    }

    fn headers_with_trace(trace_id: Uuid) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "x-trace-id",
            axum::http::HeaderValue::from_str(&trace_id.to_string()).expect("header"),
        );
        h
    }

    async fn body_bytes(resp: Response) -> Bytes {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body")
    }

    async fn body_json(resp: Response) -> Value {
        serde_json::from_slice(&body_bytes(resp).await).expect("response body is JSON")
    }

    async fn sse_mock() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(SSE_FIXTURE, "text/event-stream"))
            .mount(&server)
            .await;
        server
    }

    fn stream_request(model: &str) -> Bytes {
        Bytes::from(
            json!({
                "model": model,
                "max_tokens": 1024,
                "stream": true,
                "system": "You are a weather assistant.",
                "messages": [
                    { "role": "user", "content": "weather in Paris?" },
                    { "role": "assistant", "content": [
                        { "type": "text", "text": "let me look" },
                        { "type": "tool_use", "id": "toolu_prev", "name": "get_weather", "input": {"city":"Paris"} }
                    ]},
                    { "role": "user", "content": [
                        { "type": "tool_result", "tool_use_id": "toolu_prev", "content": "18C" }
                    ]}
                ],
                "tools": [{
                    "name": "get_weather",
                    "description": "Get the weather for a city",
                    "input_schema": {"type":"object","properties":{"city":{"type":"string"}}}
                }]
            })
            .to_string(),
        )
    }

    // ── Proof 5: byte fidelity ───────────────────────────────────────────────

    /// **SPEC §7 PROOF 5.** A fixture Anthropic SSE stream carrying `thinking` and
    /// `tool_use` blocks round-trips BYTE-IDENTICAL to the client, and the span
    /// still carries the usage.
    ///
    /// Byte equality is the assertion, not "the SDK could probably parse it": the
    /// whole reason this route forwards raw frames instead of rebuilding them is
    /// that an SDK reading `signature`, `partial_json` or a beta block type sees
    /// bytes, not our model of them. A re-framing regression — an `axum::Sse`
    /// rebuild, a normalised terminator, a dropped `event:` line — fails here.
    #[tokio::test]
    async fn streaming_sse_round_trips_byte_identical_and_the_span_has_the_usage() {
        crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
        let _bypass = LoopbackBypassGuard::new();
        let server = sse_mock().await;
        let t = tenant();
        install_byok(&t);
        let trace_id = Uuid::new_v4();
        let state = state_for(&server.uri(), in_memory_chain());

        let resp = messages_with_claims(
            state,
            headers_with_trace(trace_id),
            stream_request("claude-sonnet-4-6"),
            claims_for(&t),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream"),
        );
        let out = body_bytes(resp).await;
        assert_eq!(
            std::str::from_utf8(&out).expect("utf8"),
            SSE_FIXTURE,
            "the client must receive the provider's SSE bytes unchanged — no \
             re-framing, no re-ordering, no dropped events"
        );

        let spans = span_capture::for_trace(trace_id);
        assert_eq!(spans.len(), 1, "exactly one gateway span per request");
        let a = &spans[0].attributes;
        assert_eq!(spans[0].name, "gen_ai.chat");
        assert_eq!(a.gen_ai_usage_input_tokens, Some(1234));
        assert_eq!(
            a.gen_ai_usage_output_tokens,
            Some(57),
            "output tokens come from message_delta, MAX-merged over message_start's 1"
        );
        assert_eq!(a.gen_ai_usage_cache_read_input_tokens, Some(300));
        assert_eq!(a.gen_ai_usage_cache_creation_input_tokens, Some(12));
        assert_eq!(a.gen_ai_request_stream, Some(true));
        assert_eq!(
            a.tracelane_response_tool_names.as_ref().unwrap(),
            &["get_weather"]
        );
        let key = crate::tool_fingerprint::workspace_key(&t).unwrap();
        assert_eq!(
            a.tracelane_response_tool_arg_fps.as_ref().unwrap(),
            &[crate::tool_fingerprint::with_key(
                &key,
                r#"{"city":"Paris"}"#
            )]
        );
        assert!(
            a.gen_ai_output_messages.is_none(),
            "capture off must not retain argument text"
        );
        assert_eq!(a.gen_ai_provider_name.as_deref(), Some("anthropic"));
        assert!(
            a.gen_ai_usage_cost.is_some_and(|c| c > 0.0),
            "cost must be derived from pricing::cost_usd for a known Claude model"
        );
        assert_eq!(
            spans[0].status.code,
            tracelane_shared::span::SpanStatusCode::Ok
        );
    }

    /// B-375 (c): a client that hangs up MID-STREAM on the Anthropic-native
    /// route is recorded — the relay's Drop finalizer runs when hyper drops the
    /// body generator, exactly as `StreamFinalizer` does for the OpenAI SSE path.
    /// Before this the relay's `finish_span` sat after the loop, so a cancel
    /// recorded nothing on the route Claude Code sessions use.
    #[tokio::test]
    async fn a_client_that_hangs_up_mid_stream_is_recorded_as_cancelled() {
        // Process-global drop counter: serialised with the two stream.rs readers.
        let _serial = crate::server::DROP_COUNTER_TEST_LOCK.lock().await;
        use futures::StreamExt as _;
        let _bypass = LoopbackBypassGuard::new();
        let server = sse_mock().await;
        let t = tenant();
        install_byok(&t);
        let trace_id = Uuid::new_v4();
        let state = state_for(&server.uri(), in_memory_chain());
        let drops_before =
            crate::server::STREAMS_FINALIZED_ON_DROP.load(std::sync::atomic::Ordering::Relaxed);

        let resp = messages_with_claims(
            state,
            headers_with_trace(trace_id),
            stream_request("claude-sonnet-4-6"),
            claims_for(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Read ONE chunk, then hang up: dropping the body drops the relay's
        // generator at its suspension point — the tail of the stream never runs.
        let mut body = resp.into_body().into_data_stream();
        let first = body
            .next()
            .await
            .expect("at least one chunk")
            .expect("bytes");
        assert!(!first.is_empty());
        drop(body);
        // The finalizer records synchronously in Drop; give any spawned publish a tick.
        tokio::task::yield_now().await;

        let spans = span_capture::for_trace(trace_id);
        assert_eq!(
            spans.len(),
            1,
            "the cancelled stream must be recorded as ONE span"
        );
        let a = &spans[0].attributes;
        assert_eq!(
            a.extra.get("tracelane.stream.cancelled"),
            Some(&serde_json::Value::Bool(true)),
            "the span must say the client went away: {:?}",
            a.extra
        );
        assert_eq!(a.gen_ai_request_stream, Some(true));
        assert!(
            a.gen_ai_usage_input_tokens.is_some(),
            "the tokens seen so far (message_start's usage) are on the span"
        );
        assert_eq!(
            crate::server::STREAMS_FINALIZED_ON_DROP.load(std::sync::atomic::Ordering::Relaxed),
            drops_before + 1,
            "the finalizer counted the cancellation"
        );
    }

    /// The non-streamed twin: the provider's JSON body is returned verbatim and
    /// the same usage lands on the span.
    #[tokio::test]
    async fn non_streaming_body_is_returned_verbatim_with_the_usage_on_the_span() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(JSON_FIXTURE, "application/json"))
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t);
        let trace_id = Uuid::new_v4();
        let state = state_for(&server.uri(), in_memory_chain());

        let body = Bytes::from(
            json!({
                "model": "claude-sonnet-4-6",
                "max_tokens": 1024,
                "messages": [{ "role": "user", "content": "weather in Paris?" }]
            })
            .to_string(),
        );
        let resp =
            messages_with_claims(state, headers_with_trace(trace_id), body, claims_for(&t)).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let out = body_bytes(resp).await;
        assert_eq!(
            std::str::from_utf8(&out).expect("utf8"),
            JSON_FIXTURE,
            "a non-streamed Anthropic body must be relayed byte-for-byte"
        );

        let spans = span_capture::for_trace(trace_id);
        assert_eq!(spans.len(), 1);
        let a = &spans[0].attributes;
        assert_eq!(a.gen_ai_usage_input_tokens, Some(1234));
        assert_eq!(a.gen_ai_usage_output_tokens, Some(57));
        assert_eq!(a.gen_ai_request_stream, Some(false));
    }

    // ── Negative first: every way in that must be REFUSED ────────────────────

    /// No credential at all — the failure `crates/gateway/CLAUDE.md` names ("adding
    /// a route without replicating that sequence ships an unauthenticated
    /// endpoint"). There is no Tower auth layer to inherit.
    #[tokio::test]
    async fn messages_without_any_credential_is_rejected() {
        let state = state_for("http://127.0.0.1:1", in_memory_chain());
        let resp = messages_handler(
            State(state),
            HeaderMap::new(),
            Bytes::from(r#"{"model":"claude-sonnet-4-6","messages":[]}"#),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["type"], "error");
        assert_eq!(body["error"]["type"], "authentication_error");
    }

    /// **`x-api-key` is accepted HERE — and only here.**
    ///
    /// Three-way, because two of the three answers alone prove nothing: a request
    /// with NO credential must 401, the same request with `x-api-key` must get PAST
    /// authentication (it reaches the model-routing refusal, which sits after the
    /// scope gate), and the SAME header on `/v1/chat/completions` must still 401.
    /// A test that only checked "x-api-key is not 401 here" would pass even if the
    /// header had been wired globally.
    #[tokio::test]
    async fn x_api_key_is_accepted_on_messages_and_still_refused_on_chat_completions() {
        let state = state_for("http://127.0.0.1:1", in_memory_chain());

        let mut h = HeaderMap::new();
        h.insert(
            "x-api-key",
            axum::http::HeaderValue::from_static("unit-test-token"),
        );
        // Deliberately an unroutable model: proving the header reached the
        // validator needs an answer that is NOT 401 and does NOT dispatch.
        let resp = messages_handler(
            State(state.clone()),
            h.clone(),
            Bytes::from(r#"{"model":"gpt-4o","messages":[]}"#),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "x-api-key must route into validate_authorization on /v1/messages"
        );
        assert_eq!(body_json(resp).await["error"]["code"], "unroutable_model");

        // The same header on the OpenAI-shaped route: still unauthenticated.
        let chat = crate::server::chat_completions_handler(
            State(state),
            h,
            axum::Json(json!({ "model": "claude-sonnet-4-6", "messages": [] })),
        )
        .await;
        assert_eq!(
            chat.status(),
            StatusCode::UNAUTHORIZED,
            "x-api-key is accepted on the Anthropic routes ONLY — /v1/chat/completions \
             reads `authorization` and nothing else"
        );
    }

    /// **SPEC §7 PROOF 2 (first half).** A key without the `chat` scope is refused
    /// 403 in Anthropic error shape, and NOTHING is dispatched.
    ///
    /// "No dispatch" is asserted against the mock's own request log, not inferred
    /// from the status code: a 403 returned *after* a provider call would still be
    /// a 403, and it is the provider call that spends the customer's money.
    #[tokio::test]
    async fn a_key_without_the_chat_scope_is_refused_and_nothing_is_dispatched() {
        let _bypass = LoopbackBypassGuard::new();
        let server = sse_mock().await;
        let t = tenant();
        install_byok(&t);
        let state = state_for(&server.uri(), in_memory_chain());

        let resp = messages_with_claims(
            state,
            HeaderMap::new(),
            stream_request("claude-sonnet-4-6"),
            scoped_claims(&t, &[Scope::Read, Scope::Ingest]),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(body["type"], "error");
        assert_eq!(body["error"]["type"], "permission_error");
        assert_eq!(body["error"]["code"], "insufficient_scope");
        assert_eq!(body["error"]["required_scope"], "chat");
        assert!(
            server
                .received_requests()
                .await
                .is_some_and(|r| r.is_empty()),
            "a scope refusal must never reach the provider"
        );
        assert!(
            span_capture::for_tenant(&t).is_empty(),
            "a refusal above the ledger emits no completion span"
        );
    }

    /// ...and the gate must OPEN for the scope that is meant to pass, or it is a
    /// wall rather than a gate.
    #[tokio::test]
    async fn a_chat_scoped_key_is_allowed_through() {
        let _bypass = LoopbackBypassGuard::new();
        let server = sse_mock().await;
        let t = tenant();
        install_byok(&t);
        let state = state_for(&server.uri(), in_memory_chain());

        let resp = messages_with_claims(
            state,
            HeaderMap::new(),
            stream_request("claude-sonnet-4-6"),
            scoped_claims(&t, &[Scope::Chat]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// **SPEC §7 PROOF 2 (second half).** The audit publisher is unavailable ⇒ 503
    /// `audit_unavailable` and NO dispatch. The audit product does not serve
    /// unrecorded requests (CLAUDE.md §2 edge table).
    #[tokio::test]
    async fn an_unavailable_audit_publisher_503s_before_any_dispatch() {
        let _bypass = LoopbackBypassGuard::new();
        let server = sse_mock().await;
        let t = tenant();
        install_byok(&t);
        let state = state_for(&server.uri(), unreachable_pg_chain());

        let resp = messages_with_claims(
            state,
            HeaderMap::new(),
            stream_request("claude-sonnet-4-6"),
            claims_for(&t),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "audit_unavailable");
        assert_eq!(body["error"]["type"], "overloaded_error");
        assert!(
            server
                .received_requests()
                .await
                .is_some_and(|r| r.is_empty()),
            "an unrecorded request must never reach the provider"
        );
    }

    /// A non-Anthropic model is refused BY NAME rather than translated. One wire,
    /// one provider (spec §6) — routing a `gpt-*` here would answer an Anthropic
    /// SDK with an OpenAI body it cannot parse, and would fetch the wrong
    /// provider's BYOK credential.
    #[tokio::test]
    async fn a_non_anthropic_model_is_refused_400_and_nothing_is_dispatched() {
        let _bypass = LoopbackBypassGuard::new();
        let server = sse_mock().await;
        let t = tenant();
        install_byok(&t);
        let state = state_for(&server.uri(), in_memory_chain());

        for model in ["gpt-4o", "gemini-2.5-pro", "no-such-model-family"] {
            let resp = messages_with_claims(
                state.clone(),
                HeaderMap::new(),
                stream_request(model),
                claims_for(&t),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "model {model}");
            let body = body_json(resp).await;
            assert_eq!(body["error"]["code"], "unroutable_model", "model {model}");
            assert_eq!(body["error"]["type"], "invalid_request_error");
        }
        assert!(
            server
                .received_requests()
                .await
                .is_some_and(|r| r.is_empty()),
            "an unroutable model must never reach a provider"
        );
    }

    /// No BYOK key stored ⇒ 402 with the ADD-a-key message, not a relayed upstream
    /// 401 that reads as "my key is broken" to a user who has no key at all.
    #[tokio::test]
    async fn a_workspace_with_no_anthropic_key_is_told_to_add_one() {
        let _bypass = LoopbackBypassGuard::new();
        let server = sse_mock().await;
        // No `install_byok` — and no ANTHROPIC_API_KEY fallback is set in the
        // suite, so `resolve_provider_key` yields an empty credential.
        let t = tenant();
        let state = state_for(&server.uri(), in_memory_chain());
        let resp = messages_with_claims(
            state,
            HeaderMap::new(),
            stream_request("claude-sonnet-4-6"),
            claims_for(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            body_json(resp).await["error"]["code"],
            "provider_not_configured"
        );
    }

    /// An upstream 401 is reported as a KEY rejection, never as an outage — and
    /// the upstream body (which can echo the `x-api-key` value) is dropped.
    #[tokio::test]
    async fn an_upstream_401_maps_to_a_key_rejection_and_never_echoes_the_body() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_string("invalid x-api-key: sk-ant-leaked-value-000"),
            )
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t);
        let trace_id = Uuid::new_v4();
        let state = state_for(&server.uri(), in_memory_chain());

        let resp = messages_with_claims(
            state,
            headers_with_trace(trace_id),
            stream_request("claude-sonnet-4-6"),
            claims_for(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let raw = body_bytes(resp).await;
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("provider_key_rejected"), "{text}");
        assert!(
            !text.contains("sk-ant-leaked-value-000"),
            "the upstream error body must never be propagated: {text}"
        );
    }

    // ── OG-10 §3.1 / D7: error fidelity on the byte-faithful relay ───────────

    const PROMPT_TOO_LONG: &str = r#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 250000 tokens > 200000 maximum"}}"#;

    async fn upstream_error(template: ResponseTemplate) -> (MockServer, Response, Uuid) {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(template)
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t);
        let trace_id = Uuid::new_v4();
        let state = state_for(&server.uri(), in_memory_chain());
        let resp = messages_with_claims(
            state,
            headers_with_trace(trace_id),
            stream_request("claude-sonnet-4-6"),
            claims_for(&t),
        )
        .await;
        (server, resp, trace_id)
    }

    fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
        resp.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// **OG-10 proof 4b.** Claude Code's recovery matches on Anthropic's own wording
    /// ("prompt is too long…" → auto-compaction), so a 400 reaches it byte-for-byte.
    #[tokio::test]
    async fn an_upstream_400_is_relayed_with_its_status_and_exact_body() {
        let (_server, resp, _) = upstream_error(
            ResponseTemplate::new(400)
                .insert_header("content-type", "application/json")
                .set_body_string(PROMPT_TOO_LONG),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(header(&resp, "content-type"), Some("application/json"));
        assert!(
            header(&resp, "x-tracelane-correlation-id").is_some_and(|c| c.len() == 26),
            "our correlation id rides as a HEADER (a ULID), never injected into the body"
        );
        assert_eq!(
            std::str::from_utf8(&body_bytes(resp).await).expect("utf8"),
            PROMPT_TOO_LONG,
            "the provider's bytes, so recovery that matches on wording still matches"
        );
    }

    /// 529 `overloaded_error` stays 529 (not our 502), and the headers Claude Code's
    /// retry logic reads are forwarded.
    #[tokio::test]
    async fn a_529_is_relayed_as_529_with_the_retry_headers() {
        const OVERLOADED: &str =
            r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#;
        let (_server, resp, _) = upstream_error(
            ResponseTemplate::new(529)
                .insert_header("retry-after", "7")
                .insert_header("x-should-retry", "true")
                .insert_header("request-id", "req_011FIXTURE")
                .insert_header("anthropic-ratelimit-unified-status", "allowed_warning")
                .insert_header("anthropic-ratelimit-unified-reset", "1759329600")
                .insert_header("x-unrelated-upstream-header", "must-not-leak")
                .set_body_string(OVERLOADED),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 529);
        assert_eq!(header(&resp, "retry-after"), Some("7"));
        assert_eq!(header(&resp, "x-should-retry"), Some("true"));
        assert_eq!(header(&resp, "request-id"), Some("req_011FIXTURE"));
        assert_eq!(
            header(&resp, "anthropic-ratelimit-unified-status"),
            Some("allowed_warning")
        );
        assert_eq!(
            header(&resp, "anthropic-ratelimit-unified-reset"),
            Some("1759329600")
        );
        assert!(
            header(&resp, "x-unrelated-upstream-header").is_none(),
            "the forwarded set is an ALLOWLIST"
        );
        assert_eq!(
            std::str::from_utf8(&body_bytes(resp).await).expect("utf8"),
            OVERLOADED
        );
    }

    /// An HTTP-date `Retry-After` is re-emitted as integer seconds (what the protocol wants).
    #[tokio::test]
    async fn a_date_valued_retry_after_is_forwarded_as_integer_seconds() {
        let at = (chrono::Utc::now() + chrono::Duration::seconds(90)).to_rfc2822();
        let (_server, resp, _) = upstream_error(
            ResponseTemplate::new(429)
                .insert_header("retry-after", at.replace("+0000", "GMT").as_str())
                .set_body_string(
                    r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}"#,
                ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let secs: u64 = header(&resp, "retry-after")
            .and_then(|v| v.parse().ok())
            .expect("integer seconds");
        assert!((85..=91).contains(&secs), "{secs}");
    }

    /// 401 / 403 / 407 keep the key-rejected mapping — those bodies echo `x-api-key`.
    #[tokio::test]
    async fn a_401_403_407_body_that_echoes_the_key_is_never_relayed() {
        for status in [401u16, 403, 407] {
            let (_server, resp, _) = upstream_error(
                ResponseTemplate::new(status).set_body_string(
                    r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key: sk-ant-api03-LEAKEDLEAKEDLEAKEDLEAKED0000"}}"#,
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{status}");
            let raw = body_bytes(resp).await;
            let text = String::from_utf8_lossy(&raw);
            assert!(text.contains("provider_key_rejected"), "{status}: {text}");
            assert!(!text.contains("LEAKED"), "{status}: {text}");
        }
    }

    /// A 4xx body is scrubbed on the way out, and what leaves is still JSON.
    #[tokio::test]
    async fn a_relayed_error_body_is_scrubbed_and_stays_json() {
        let (_server, resp, _) = upstream_error(ResponseTemplate::new(400).set_body_string(
            r#"{"type":"error","error":{"type":"invalid_request_error","message":"bad value sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ and the unit-test-anthropic-key-do-not-use-in-prod"}}"#,
        ))
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let raw = body_bytes(resp).await;
        let v: Value = serde_json::from_slice(&raw).expect("still JSON");
        let msg = v["error"]["message"].as_str().expect("message");
        assert!(msg.starts_with("bad value"), "{msg}");
        assert!(!msg.contains("ZZZZ"), "a key shape must be scrubbed: {msg}");
        assert!(
            !msg.contains("unit-test-anthropic-key"),
            "the tenant's own key verbatim must be removed: {msg}"
        );
    }

    /// The 64 KiB cap: an oversized body is NOT relayed truncated (that would be broken
    /// JSON); the original status survives in an Anthropic-shaped error of our own.
    #[tokio::test]
    async fn an_oversized_error_body_keeps_its_status_and_stays_json() {
        let big = format!(
            r#"{{"type":"error","error":{{"type":"api_error","message":"{}"}}}}"#,
            "x".repeat(70 * 1024)
        );
        let (_server, resp, _) =
            upstream_error(ResponseTemplate::new(500).set_body_string(big)).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let raw = body_bytes(resp).await;
        assert!(raw.len() < 4096, "the oversized body is not relayed");
        let v: Value = serde_json::from_slice(&raw).expect("JSON");
        assert_eq!(v["type"], "error");
    }

    /// A non-JSON error body (a proxy's HTML page) is not relayed as if it were Anthropic's.
    #[tokio::test]
    async fn a_non_json_error_body_keeps_its_status_in_our_own_json() {
        let (_server, resp, _) = upstream_error(
            ResponseTemplate::new(502).set_body_string("<html><body>Bad gateway</body></html>"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let raw = body_bytes(resp).await;
        let v: Value = serde_json::from_slice(&raw).expect("JSON");
        assert_eq!(v["type"], "error");
        assert!(!String::from_utf8_lossy(&raw).contains("<html>"));
    }

    /// `count_tokens` follows the same rule.
    #[tokio::test]
    async fn count_tokens_relays_an_upstream_400_unmodified() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages/count_tokens"))
            .respond_with(ResponseTemplate::new(400).set_body_string(PROMPT_TOO_LONG))
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t);
        let resp = count_tokens_with_claims(
            state_for(&server.uri(), in_memory_chain()),
            HeaderMap::new(),
            Bytes::from(
                json!({"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]})
                    .to_string(),
            ),
            claims_for(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(header(&resp, "x-tracelane-correlation-id").is_some());
        assert_eq!(
            std::str::from_utf8(&body_bytes(resp).await).expect("utf8"),
            PROMPT_TOO_LONG
        );
    }

    /// The error span still records an error, with the gateway's own classification.
    #[tokio::test]
    async fn a_relayed_error_still_records_an_error_span() {
        let (_server, resp, trace_id) =
            upstream_error(ResponseTemplate::new(529).set_body_string(PROMPT_TOO_LONG)).await;
        assert_eq!(resp.status().as_u16(), 529);
        let spans = span_capture::for_trace(trace_id);
        assert_eq!(spans.len(), 1, "one error span per failed request");
        assert_eq!(
            spans[0].status.code,
            tracelane_shared::span::SpanStatusCode::Error
        );
    }

    // ── count_tokens ─────────────────────────────────────────────────────────

    /// `count_tokens` forwards and relays verbatim — and emits NO span.
    ///
    /// The audit chain here is the UNREACHABLE-Postgres one, so the absence of a
    /// ledger row is proven too: if this route published one it would 503 exactly
    /// as `/v1/messages` does. Two properties, one arrangement.
    #[tokio::test]
    async fn count_tokens_forwards_verbatim_with_no_span_and_no_ledger_row() {
        let _bypass = LoopbackBypassGuard::new();
        const COUNT_BODY: &str = r#"{"input_tokens":2095}"#;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages/count_tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(COUNT_BODY, "application/json"))
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t);
        let state = state_for(&server.uri(), unreachable_pg_chain());

        let resp = count_tokens_with_claims(
            state,
            HeaderMap::new(),
            Bytes::from(
                json!({
                    "model": "claude-sonnet-4-6",
                    "messages": [{ "role": "user", "content": "hi" }]
                })
                .to_string(),
            ),
            claims_for(&t),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "count_tokens must not publish a ledger row — a fail-closed publish \
             against the unreachable control plane would have 503'd here"
        );
        assert_eq!(
            std::str::from_utf8(&body_bytes(resp).await).expect("utf8"),
            COUNT_BODY,
        );
        assert!(
            span_capture::for_tenant(&t).is_empty(),
            "count_tokens is not an inference and emits no span"
        );
        assert_eq!(
            server.received_requests().await.map(|r| r.len()),
            Some(1),
            "exactly one forwarded request"
        );
    }

    /// The scope gate covers `count_tokens` too — it uses the tenant's decrypted
    /// BYOK credential, and a read-only key must not reach one.
    #[tokio::test]
    async fn count_tokens_is_scope_gated_like_the_inference_route() {
        let t = tenant();
        let state = state_for("http://127.0.0.1:1", in_memory_chain());
        let resp = count_tokens_with_claims(
            state,
            HeaderMap::new(),
            Bytes::from(r#"{"model":"claude-sonnet-4-6","messages":[]}"#),
            scoped_claims(&t, &[Scope::Read]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_json(resp).await["error"]["code"], "insufficient_scope");
    }

    // ── The isolation proof (spec §7 proof 6) ────────────────────────────────

    /// **SPEC §7 PROOF 6.** `chat_completions_handler` gains NO call into this
    /// module — the hot path is byte-unchanged by this feature.
    ///
    /// INCLUDE_STR GUARD (B-385 2c) — a LITERAL-ABSENCE guard, kept. Since B-385
    /// the two routes SHARE `crate::admission`, deliberately; what stays refused
    /// is the chat handler reaching into THIS module's relay.
    ///
    /// Grepping the checked-in source is a real, falsifiable assertion rather than
    /// a description: adding `crate::anthropic_messages::…` anywhere inside the
    /// chat handler fails here. The handler body is extracted by brace matching
    /// from its `async fn` marker, so a call added ELSEWHERE (the route mount in
    /// `server.rs`, which must exist) does not false-positive. B-385 §2d moved the
    /// handler to `server/chat.rs`; the mounts stay in `server.rs`, so the two
    /// halves of this test read two files.
    ///
    /// The needle is assembled at runtime and never appears un-split in this file,
    /// including in this comment — `include_str!` would otherwise be clean while
    /// this test matched its own text, which is exactly how
    /// `both_methods_on_v1_traces_coexist`'s first version passed against a route
    /// that had already been changed.
    #[test]
    fn chat_handler_gains_no_call_into_this_module() {
        let src = include_str!("server.rs");
        let chat = include_str!("server/chat.rs");
        let marker = format!("{}{}", "async fn chat_completions_", "handler(");
        let start = chat.find(&marker).expect("chat handler");
        let body = brace_body(&chat[start..]).expect("chat handler body");

        let needle = format!("{}{}", "crate::anthropic_", "messages");
        assert!(
            !body.contains(&needle),
            "chat_completions_handler now calls into the Anthropic Messages module — \
             GWY-47 must add nothing to the hot path"
        );

        // And the routes ARE mounted, so this is an isolation proof rather than a
        // proof that the feature does not exist.
        let squeezed: String = src.chars().filter(|c| !c.is_whitespace()).collect();
        for route in ["/v1/messages", "/v1/messages/count_tokens"] {
            let mount = format!(r#".route("{route}","#);
            let mount: String = mount.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(
                squeezed.contains(&mount),
                "{route} is not mounted in the unconditional router"
            );
        }
    }

    /// The substring of `s` from its first `{` to the matching `}`.
    fn brace_body(s: &str) -> Option<&str> {
        let open = s.find('{')?;
        let mut depth = 0usize;
        for (i, c) in s[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&s[open..=open + i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    // ── Unit tests for the pure parts ────────────────────────────────────────

    #[test]
    fn usage_merges_with_max_not_sum() {
        // B-104: `message_start` carries the input count with output 0, and
        // `message_delta` carries the final output with no input. Summing would
        // double-count a provider that repeats a field.
        let mut u = UsageAcc::default();
        u.merge(&json!({"input_tokens": 1234, "output_tokens": 1, "cache_read_input_tokens": 300}));
        u.merge(&json!({"output_tokens": 57}));
        u.merge(&json!({"output_tokens": 12}));
        assert_eq!(u.input, 1234);
        assert_eq!(u.output, 57, "MAX, never a sum and never last-write-wins");
        assert_eq!(u.cache_read, Some(300));
        assert_eq!(u.cache_creation, None, "absent stays absent, never 0");
    }

    #[test]
    fn split_frame_handles_both_terminators_and_waits_for_a_complete_frame() {
        let mut buf = b"event: a\ndata: 1\n\n".to_vec();
        assert_eq!(
            split_frame(&mut buf).as_deref(),
            Some(&b"event: a\ndata: 1\n\n"[..])
        );
        assert!(buf.is_empty());

        let mut buf = b"event: a\r\ndata: 1\r\n\r\nevent: b".to_vec();
        assert_eq!(
            split_frame(&mut buf).as_deref(),
            Some(&b"event: a\r\ndata: 1\r\n\r\n"[..])
        );
        assert_eq!(buf, b"event: b");
        assert!(
            split_frame(&mut buf).is_none(),
            "a partial frame must stay buffered, not be emitted early"
        );
    }

    #[test]
    fn the_anthropic_read_model_keeps_what_the_rails_need() {
        let body: Value =
            serde_json::from_slice(&stream_request("claude-sonnet-4-6")).expect("fixture parses");
        let req = to_chat_request(&body).expect("translates");
        assert_eq!(req.system.as_deref(), Some("You are a weather assistant."));
        assert_eq!(req.messages.len(), 3);
        assert_eq!(req.tools.as_ref().map(Vec::len), Some(1));
        assert_eq!(req.tools.as_ref().expect("tools")[0].name, "get_weather");
        // The tool RESULT must survive: it is the untrusted content R4 reads.
        let last = req.messages.last().expect("a message");
        match &last.content {
            MessageContent::Parts(parts) => match &parts[0] {
                ContentPart::ToolResult { content, .. } => assert_eq!(content, "18C"),
                other => panic!("expected a tool_result part, got {other:?}"),
            },
            other => panic!("expected content parts, got {other:?}"),
        }
    }

    #[test]
    fn a_body_that_is_not_a_messages_request_is_refused_by_the_read_model() {
        assert!(to_chat_request(&json!({})).is_err());
        assert!(to_chat_request(&json!({ "model": "claude-sonnet-4-6" })).is_err());
        assert!(to_chat_request(&json!({ "messages": [] })).is_err());
        // ...and a minimal legal request is NOT refused.
        assert!(to_chat_request(&json!({ "model": "claude-sonnet-4-6", "messages": [] })).is_ok());
    }

    /// The egress redaction rewrites the bytes that actually leave, not a read
    /// model nothing sends. A map built against the wrong object would redact the
    /// verdict and ship the secret.
    #[test]
    fn egress_redaction_rewrites_the_outgoing_body_not_the_read_model() {
        let mut body = json!({
            "model": "claude-sonnet-4-6",
            "system": "key is sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "messages": [{
                "role": "user",
                "content": [{ "type": "text", "text": "and my email is nobody@example.com" }]
            }]
        });
        let before = body.clone();
        let map =
            crate::guardrail::egress::redact_relay_body(&mut body).expect("redactable in place");
        assert!(
            !map.is_empty(),
            "the fixture must actually contain something to redact"
        );
        assert_ne!(body, before, "the OUTGOING body is what changes");
        let rendered = body.to_string();
        assert!(!rendered.contains("nobody@example.com"), "{rendered}");
    }

    /// A non-429 upstream 4xx is one tenant's dead key, not an observation about
    /// Anthropic — feeding it to the tenant-less breaker would let that tenant open
    /// the circuit for everyone.
    #[test]
    fn the_breaker_is_fed_only_real_upstream_faults() {
        use crate::circuit_breaker::Outcome;
        assert_eq!(breaker_observation(Some(200)), Some(Outcome::Success));
        assert_eq!(breaker_observation(Some(401)), None);
        assert_eq!(breaker_observation(Some(404)), None);
        assert_eq!(breaker_observation(Some(400)), None);
        assert_eq!(
            breaker_observation(Some(429)),
            None,
            "F4: a 429 is one tenant's quota under BYOK"
        );
        assert_eq!(breaker_observation(Some(500)), Some(Outcome::UpstreamFault));
        assert_eq!(
            breaker_observation(None),
            Some(Outcome::CredentialFault),
            "SB: a status-less failure nobody classified is never provider evidence"
        );
    }

    #[test]
    fn x_api_key_is_wrapped_into_bearer_without_doubling_an_existing_prefix() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-api-key",
            axum::http::HeaderValue::from_static("tlane_abc"),
        );
        assert_eq!(authorization_value(&h).as_deref(), Some("Bearer tlane_abc"));

        let mut h = HeaderMap::new();
        h.insert(
            "x-api-key",
            axum::http::HeaderValue::from_static("Bearer tlane_abc"),
        );
        assert_eq!(authorization_value(&h).as_deref(), Some("Bearer tlane_abc"));

        // `authorization` wins when both are present, and an empty header is absent.
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer jwt"),
        );
        h.insert(
            "x-api-key",
            axum::http::HeaderValue::from_static("tlane_abc"),
        );
        assert_eq!(authorization_value(&h).as_deref(), Some("Bearer jwt"));

        let mut h = HeaderMap::new();
        h.insert("x-api-key", axum::http::HeaderValue::from_static(""));
        assert_eq!(authorization_value(&h), None);
        assert_eq!(authorization_value(&HeaderMap::new()), None);
    }

    /// The client's `anthropic-version` / `anthropic-beta` are what reach Anthropic
    /// — pinning our own would change the response shape under an SDK that asked
    /// for something else.
    #[tokio::test]
    async fn the_clients_anthropic_version_and_beta_headers_are_forwarded() {
        let _bypass = LoopbackBypassGuard::new();
        let server = sse_mock().await;
        let t = tenant();
        install_byok(&t);
        let state = state_for(&server.uri(), in_memory_chain());

        let mut h = HeaderMap::new();
        h.insert(
            "anthropic-version",
            axum::http::HeaderValue::from_static("2024-10-22"),
        );
        h.insert(
            "anthropic-beta",
            axum::http::HeaderValue::from_static("fine-grained-tool-streaming-2025-05-14"),
        );
        let body = stream_request("claude-sonnet-4-6");
        let resp = messages_with_claims(state, h, body.clone(), claims_for(&t)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_bytes(resp).await;

        let reqs = server.received_requests().await.expect("request log");
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0]
                .headers
                .get("anthropic-version")
                .map(|v| v.as_bytes()),
            Some(&b"2024-10-22"[..]),
        );
        assert_eq!(
            reqs[0].headers.get("anthropic-beta").map(|v| v.as_bytes()),
            Some(&b"fine-grained-tool-streaming-2025-05-14"[..]),
        );
        assert_eq!(
            reqs[0].body, body,
            "the ORIGINAL request bytes are what reach Anthropic — nothing is \
             re-serialised on the way out"
        );
    }
    #[tokio::test]
    async fn kya_messages_records_header_identity_and_client_without_user_agent() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(JSON_FIXTURE, "application/json"))
            .mount(&server)
            .await;
        let tenant = tenant();
        install_byok(&tenant);
        let trace = Uuid::new_v4();
        let mut headers = headers_with_trace(trace);
        headers.insert("x-tracelane-agent-name", "KYA-Proof".parse().unwrap());
        headers.insert(
            "user-agent",
            "claude-cli/2.1.281 private-machine-metadata"
                .parse()
                .unwrap(),
        );
        let body=Bytes::from(json!({"model":"claude-sonnet-4-6","max_tokens":8,"messages":[{"role":"user","content":"hello"}]}).to_string());
        let response = messages_with_claims(
            state_for(&server.uri(), in_memory_chain()),
            headers,
            body,
            claims_for(&tenant),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let spans = span_capture::for_trace(trace);
        assert_eq!(spans.len(), 1);
        let attrs = &spans[0].attributes;
        assert_eq!(attrs.gen_ai_agent_name.as_deref(), Some("kya-proof"));
        assert_eq!(attrs.tracelane_client_name.as_deref(), Some("claude-code"));
        assert_eq!(attrs.tracelane_agent_name_source.as_deref(), Some("header"));
        let stored = serde_json::to_string(&spans[0]).unwrap();
        assert!(!stored.contains("claude-cli/"));
        assert!(!stored.contains("private-machine-metadata"));
    }

    #[tokio::test]
    async fn anthropic_buffered_and_sse_spans_record_response_identity() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(JSON_FIXTURE, "application/json"))
            .mount(&server)
            .await;
        let t = tenant();
        install_byok(&t);
        let trace = Uuid::new_v4();
        let body = Bytes::from(
            json!({
                "model":"claude-sonnet-4-6", "max_tokens": 8,
                "messages":[{"role":"user","content":"weather?"}]
            })
            .to_string(),
        );
        let resp = messages_with_claims(
            state_for(&server.uri(), in_memory_chain()),
            headers_with_trace(trace),
            body,
            claims_for(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_bytes(resp).await;
        let spans = span_capture::for_trace(trace);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].attributes.gen_ai_response_id.as_deref(),
            Some("msg_01FIXJ")
        );
        assert_eq!(
            spans[0].attributes.gen_ai_response_finish_reasons,
            Some(vec!["tool_calls".into()])
        );

        let sse = sse_mock().await;
        let trace = Uuid::new_v4();
        let resp = messages_with_claims(
            state_for(&sse.uri(), in_memory_chain()),
            headers_with_trace(trace),
            stream_request("claude-sonnet-4-6"),
            claims_for(&t),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = body_bytes(resp).await;
        let spans = span_capture::for_trace(trace);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].attributes.gen_ai_response_id.as_deref(),
            Some("msg_01FIX")
        );
        assert_eq!(
            spans[0].attributes.gen_ai_response_finish_reasons,
            Some(vec!["tool_calls".into()])
        );
    }

    #[tokio::test]
    async fn anthropic_finish_span_captures_text_and_tool_use_under_the_output_policy() {
        let t = tenant();
        let trace = Uuid::new_v4();
        let now = chrono::Utc::now();
        let parsed: Value = serde_json::from_str(JSON_FIXTURE).unwrap();
        let mut calls = crate::server::ToolCallAccumulator::default();
        calls.absorb_anthropic(&parsed);
        let mut served = crate::server::ServedMeta::default();
        served.absorb(
            Some("msg_01FIXJ".into()),
            Some("claude-sonnet-4-6".into()),
            None,
        );
        let ctx = SpanContext {
            tenant_id: t,
            trace_id: trace,
            parent_span_id: None,
            model: "claude-sonnet-4-6".into(),
            identity: crate::server::CallerIdentity::default(),
            request_start: now,
            dispatch_ts: now,
            api_key_id: None,
            captured_input: None,
            capture: crate::server::config::ContentCapture {
                input: false,
                output: true,
                max_field_bytes: 64 * 1024,
            },
            request_config: crate::server::RequestConfig::default(),
            aft_id: None,
            dispatch_attempts: Vec::new(),
        };
        let long_text = "x".repeat(70_000);
        finish_span(
            &state_for("http://127.0.0.1:1", in_memory_chain()),
            ctx,
            UsageAcc::default(),
            FinishOutcome {
                tool_calls: Some(&calls),
                output_tool_calls: Some(&calls),
                output_text: Some(&long_text),
                served,
                finish_reason: Some(crate::providers::FinishReason::ToolCalls),
                stream: false,
                ttft_us: None,
                provider_complete_ts: now,
                error_reason: None,
                cancelled: false,
            },
        );
        let spans = span_capture::for_trace(trace);
        assert_eq!(spans.len(), 1);
        let a = &spans[0].attributes;
        assert_eq!(a.gen_ai_response_id.as_deref(), Some("msg_01FIXJ"));
        assert_eq!(
            a.gen_ai_response_finish_reasons,
            Some(vec!["tool_calls".into()])
        );
        let output = a.gen_ai_output_messages.as_ref().unwrap();
        let text = output[0]["content"].as_str().unwrap();
        assert!(text.len() <= 64 * 1024);
        assert!(text.ends_with("…[truncated]"));
        assert_eq!(output[0]["tool_calls"][0]["name"], "get_weather");
        assert_eq!(output[0]["tool_calls"][0]["input"], r#"{"city":"Paris"}"#);
    }

    #[test]
    fn anthropic_released_sse_frames_accumulate_only_delivered_text_and_tools() {
        let mut fin = RelayFinalizer {
            tool_calls: crate::server::ToolCallAccumulator::default(),
            delivered_tool_calls: crate::server::ToolCallAccumulator::default(),
            output_ring: Some(String::new()),
            output_cap: 64 * 1024,
            served: crate::server::ServedMeta::default(),
            finish_reason: None,
            state: state_for("http://127.0.0.1:1", in_memory_chain()),
            ctx: None,
            usage: UsageAcc::default(),
            first_byte_ts: None,
            error_reason: None,
            finished: true,
        };
        let mut frames = SSE_FIXTURE.as_bytes().to_vec();
        while let Some(raw) = split_frame(&mut frames) {
            fin.observe_metadata(&raw);
            fin.record_delivered(&raw);
        }
        assert_eq!(fin.served.id.as_deref(), Some("msg_01FIX"));
        assert_eq!(
            fin.finish_reason,
            Some(crate::providers::FinishReason::ToolCalls)
        );
        assert_eq!(
            fin.output_ring.as_deref(),
            Some("Checking the weather for you.")
        );
        let calls = fin.delivered_tool_calls.for_span();
        assert_eq!(calls[0].1.as_deref(), Some("get_weather"));
        assert_eq!(calls[0].2, r#"{"city":"Paris"}"#);
    }

    #[tokio::test]
    async fn messages_provider_not_configured_error_span_keeps_captured_input() {
        let t = tenant();
        let mut state = state_for("http://127.0.0.1:1", in_memory_chain());
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
        let body = Bytes::from(
            json!({
                "model":"claude-sonnet-4-6", "max_tokens":8,
                "messages":[{"role":"user","content":"CANARY_MESSAGES_ERROR"}]
            })
            .to_string(),
        );
        let resp =
            messages_with_claims(state, headers_with_trace(trace), body, claims_for(&t)).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let spans = span_capture::for_trace(trace);
        assert_eq!(spans.len(), 1);
        let input = spans[0]
            .attributes
            .gen_ai_input_messages
            .as_ref()
            .expect("error span input");
        assert!(input.to_string().contains("CANARY_MESSAGES_ERROR"));
    }
}

#[cfg(test)]
mod capture_image_tests {
    use super::*;

    #[test]
    fn anthropic_image_is_marked_and_captured_without_bytes() {
        let body = json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 8,
            "messages": [{"role":"user", "content":[
                {"type":"image", "source":{"type":"base64", "media_type":"image/png", "data":"SECRET_IMAGE_BYTES"}}
            ]}]
        });
        let req = to_chat_request(&body).unwrap();
        assert_eq!(crate::request_support::non_text_part_count(&req), 1);
        let capture = crate::server::config::ContentCapture {
            input: true,
            output: false,
            max_field_bytes: 64 * 1024,
        };
        let mut attrs = tracelane_shared::SpanAttributes::default();
        CapturedInput::build(capture, &req)
            .unwrap()
            .apply(&mut attrs);
        crate::server::RequestConfig::build(&req).apply(&mut attrs);
        assert_eq!(attrs.tracelane_request_non_text_parts, Some(1));
        let recorded = attrs.gen_ai_input_messages.unwrap().to_string();
        assert!(recorded.contains("image/png"));
        assert!(!recorded.contains("SECRET_IMAGE_BYTES"));
    }
}

#[cfg(test)]
#[tokio::test]
async fn og30_native_initial_text_and_tool_frames_are_refused_before_yield() {
    for value in [
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":"person@example.com"}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"person@example.com"}}),
    ] {
        let raw = Bytes::from(format!("data: {value}\n\n"));
        let frame = classify_frame(raw, &mut UsageAcc::default(), &mut None);
        let mut relay = Relay::new(crate::guardrail::policy_tests::output_guard());
        assert!(matches!(
            relay
                .push(
                    frame,
                    Usage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_read_input_tokens: None,
                        cache_creation_input_tokens: None
                    }
                )
                .await,
            Release::Blocked(_, "OUTPUT_POLICY_UNSCANNABLE")
        ));
    }
}

#[cfg(test)]
#[tokio::test]
async fn og30_redacted_delta_does_not_clear_raw_initial_text() {
    let mut relay = Relay::new(crate::guardrail::policy_tests::output_guard_mode("redact"));
    let mut usage = UsageAcc::default();
    let mut error = None;
    for (value, blocked) in [
        (
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"person@example.com"}}),
            false,
        ),
        (
            json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":"person@example.com"}}),
            true,
        ),
    ] {
        let frame = classify_frame(
            Bytes::from(format!("data: {value}\n\n")),
            &mut usage,
            &mut error,
        );
        let result = relay.push(frame, usage.as_usage()).await;
        assert_eq!(matches!(result, Release::Blocked(_, _)), blocked);
        if let Release::Bytes(frames) = result {
            assert!(frames.is_empty());
        }
    }
}
