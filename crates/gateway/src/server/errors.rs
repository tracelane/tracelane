//! Typed client-facing error responses shared by the handlers (B-385 §2d split of `server.rs`).
//!
//! Every body here is ALLOWLIST-constructed and scrubbed; an upstream provider's
//! body never crosses this boundary (a bad-BYOK 401 echoes the tenant's own key).

use axum::http::StatusCode;
use axum::response::IntoResponse as _;

/// How a provider dispatch failed, in the vocabulary the span's `status.message`
/// and the client's `error` code both use.
///
/// One definition so the countable reason and the returned status can never
/// disagree — #3 was exactly that disagreement (a 502 on the wire, no
/// error span behind it, a structural 0% error rate on `/slo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DispatchFailure {
    /// Upstream 401/403 — the tenant's BYOK key was rejected. ROTATE it.
    KeyRejected,
    /// Upstream 429 — the caller is over the provider's limit. Not an outage.
    RateLimited,
    /// Upstream 404 — the provider does not serve this model for this account.
    ModelNotFound,
    /// Any other upstream 4xx. The upstream rejected the REQUEST; we cannot say
    /// why without propagating a body that may echo the credential.
    RequestRejected(u16),
    /// Timeout, connection failure, or 5xx after retry. A genuine outage.
    Unavailable,
    Timeout(crate::routing::deadlines::Timeout),
}

impl DispatchFailure {
    /// The `status.message` written onto the error span, and the `error` code
    /// returned to the caller. Same token for both, by construction.
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::KeyRejected => "provider_key_rejected",
            Self::RateLimited => "provider_rate_limited",
            Self::ModelNotFound => "model_not_found",
            Self::RequestRejected(_) => "provider_request_rejected",
            Self::Unavailable => "provider_unavailable",
            Self::Timeout(_) => "upstream_timeout",
        }
    }
}

/// Classify a dispatch error from its typed upstream status.
///
/// Mirrors the inline cascade in [`super::chat::chat_completions_handler`]
/// exactly; that cascade predates this helper and should be collapsed onto it,
/// which is a pure refactor and deliberately not bundled into this change.
pub(super) fn classify_dispatch_error(err: &anyhow::Error) -> DispatchFailure {
    if let Some(timeout) = crate::routing::deadlines::Timeout::find(err.as_ref()) {
        return DispatchFailure::Timeout(timeout);
    }
    let Some(http) = err.downcast_ref::<crate::providers::ProviderHttpError>() else {
        return DispatchFailure::Unavailable;
    };
    if http.is_auth_rejection() {
        DispatchFailure::KeyRejected
    } else if http.is_rate_limited() {
        DispatchFailure::RateLimited
    } else if http.is_model_not_found() {
        DispatchFailure::ModelNotFound
    } else if http.is_unclassified_client_error() {
        DispatchFailure::RequestRejected(http.status)
    } else {
        DispatchFailure::Unavailable
    }
}

/// Client-facing response for a classified dispatch failure.
///
/// Allowlist-constructed and scrubbed by [`provider_error_response`] — the
/// upstream body never crosses this boundary.
pub(super) fn dispatch_failure_response(
    failure: DispatchFailure,
    upstream: &'static str,
    // OG-10: the upstream's own `Retry-After` for a 429/503, from [`upstream_retry_after_secs`].
    upstream_retry_after: Option<u64>,
) -> axum::response::Response {
    match failure {
        DispatchFailure::Timeout(timeout) => timeout.response(),
        DispatchFailure::KeyRejected => provider_error_response(
            StatusCode::UNAUTHORIZED,
            failure.reason(),
            Some(
                "the configured provider key was rejected by the upstream provider — verify the key for this provider",
            ),
            Some(upstream),
            None,
        ),
        DispatchFailure::RateLimited => provider_error_response_retry(
            StatusCode::TOO_MANY_REQUESTS,
            failure.reason(),
            Some(
                "the upstream provider rate-limited or quota-exhausted this request — retry later, or check the provider account's plan and billing",
            ),
            Some(upstream),
            None,
            upstream_retry_after,
            Some("60"),
        ),
        DispatchFailure::ModelNotFound => provider_error_response(
            StatusCode::NOT_FOUND,
            failure.reason(),
            Some(
                "the upstream provider does not recognise this model for this account — check the model name and that your provider account has access to it",
            ),
            Some(upstream),
            None,
        ),
        DispatchFailure::RequestRejected(status) => {
            let message = format!(
                "the upstream provider rejected this request with HTTP {status}. \
                 This is not a Tracelane outage — it is usually either a provider \
                 key that is invalid or expired for this account, or a request the \
                 provider could not accept (model, parameters, or payload). \
                 Verify the key for this provider, then the request itself."
            );
            provider_error_response(
                // Mirror the upstream status. 401/403/404/429 are claimed above
                // and cannot reach here; anything unrepresentable degrades to
                // 400 — still client-class, never a 5xx that blames us.
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                failure.reason(),
                Some(&message),
                Some(upstream),
                None,
            )
        }
        DispatchFailure::Unavailable => provider_error_response_retry(
            StatusCode::BAD_GATEWAY,
            "provider unavailable",
            None,
            None,
            None,
            upstream_retry_after,
            None,
        ),
    }
}

/// The fail-closed response for a model that matches NO provider in the
/// canonical map. Returned INSTEAD of routing to a default provider — no key is
/// resolved, no upstream call is made. 400 (the caller sent an unroutable model).
/// The model string is echoed back (it is the caller's own input, not a secret)
/// so they can correct it; scrubbed defensively in case a key was pasted as a
/// "model".
pub(crate) fn unroutable_model_response(model: &str) -> axum::response::Response {
    let mut map = serde_json::Map::new();
    map.insert("error".into(), "unroutable_model".into());
    map.insert(
        "message".into(),
        "no provider is configured to serve this model — use a supported model, \
         or prefix it with a provider (e.g. openrouter/<model>, together/<model>)"
            .into(),
    );
    map.insert("model".into(), model.into());
    let raw = serde_json::to_vec(&serde_json::Value::Object(map))
        .unwrap_or_else(|_| b"{\"error\":\"unroutable_model\"}".to_vec());
    // Defense in depth: scrub in case a key was pasted into the `model` field.
    let scrubbed = tracelane_shared::redact::scrub(&raw);
    let mut resp = (StatusCode::BAD_REQUEST, scrubbed).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp
}

/// `GWY-49`: the one sentence both wires (OpenAI-shaped chat/embeddings, Anthropic-shaped
/// `/v1/messages`) return for an unsatisfiable constraint. `eligible_default_count` is how
/// many providers the gateway's table currently vouches for at ALL — when it is zero the
/// advice "choose a provider that does" would be empty, so the message says so instead of
/// pointing at a choice that does not exist yet.
pub(crate) fn zdr_unsatisfiable_message(eligible_default_count: usize) -> String {
    let base = "this request requires zero data retention (x-tracelane-zdr: required) and the \
                provider serving this model does not carry a verified no-retention, no-training \
                guarantee for every account";
    if eligible_default_count == 0 {
        format!(
            "{base} — and no provider in this gateway's capability table carries one yet; \
             drop the constraint until the table is populated"
        )
    } else {
        format!(
            "{base} — choose a model on one of the {eligible_default_count} provider(s) that \
             do, or drop the constraint"
        )
    }
}

/// `GWY-49`: the request carried `x-tracelane-zdr: required` and the provider that
/// serves this model does not carry a `default` zero-data-retention capability in the
/// reference table (or the table is unreadable). 400, fail-CLOSED, no provider
/// contacted. The body names the model and the provider so the customer knows WHICH
/// promise is missing — never the table's internals.
pub(crate) fn zdr_unsatisfiable_response(
    model: &str,
    provider: &str,
    eligible_default_count: usize,
) -> axum::response::Response {
    let mut map = serde_json::Map::new();
    map.insert("error".into(), "zdr_unsatisfiable".into());
    map.insert(
        "message".into(),
        zdr_unsatisfiable_message(eligible_default_count).into(),
    );
    map.insert("model".into(), model.into());
    map.insert("provider".into(), provider.into());
    map.insert(
        "eligible_provider_count".into(),
        serde_json::Value::from(eligible_default_count),
    );
    json_400(map, b"{\"error\":\"zdr_unsatisfiable\"}")
}

/// `GWY-49`: the sentence for a header value this gateway does not understand.
pub(crate) const INVALID_ZDR_CONSTRAINT_MESSAGE: &str =
    "x-tracelane-zdr accepts exactly one value: `required`";

/// `GWY-49`: `x-tracelane-zdr` carried a value this gateway does not understand. A
/// compliance header is never guessed at — 400 before any routing.
pub(crate) fn invalid_zdr_constraint_response(value: &str) -> axum::response::Response {
    let mut map = serde_json::Map::new();
    map.insert("error".into(), "invalid_zdr_constraint".into());
    map.insert("message".into(), INVALID_ZDR_CONSTRAINT_MESSAGE.into());
    // Bounded echo of what was sent, so a typo is visible; scrubbed below like every body.
    map.insert(
        "received".into(),
        value.chars().take(64).collect::<String>().into(),
    );
    json_400(map, b"{\"error\":\"invalid_zdr_constraint\"}")
}

fn json_400(
    map: serde_json::Map<String, serde_json::Value>,
    fallback: &[u8],
) -> axum::response::Response {
    let raw =
        serde_json::to_vec(&serde_json::Value::Object(map)).unwrap_or_else(|_| fallback.to_vec());
    let scrubbed = tracelane_shared::redact::scrub(&raw);
    let mut resp = (StatusCode::BAD_REQUEST, scrubbed).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp
}

/// Build a client-facing provider-error response with a defense-in-depth
/// redaction backstop.
///
/// The body is **allowlist-constructed** — our typed `error` code, an optional
/// STATIC `message`, and the provider NAME only. The upstream provider's body and
/// headers are NEVER included (a bad-BYOK 401 body echoes the tenant's own key; a
/// verbose 5xx body can carry internal detail). Belt-and-suspenders: the
/// serialized body is then run through `tracelane_shared::redact::scrub`, so any
/// key-shaped string (`sk-`, `AIza`, `AQ.`, `xai-`, `tlane_`, `Bearer …`, an
/// `authorization`/`x-api-key` field, …) that ever slips into a field is scrubbed
/// before it reaches the client. `Content-Type` is forced to `application/json`
/// (scrub returns bytes, which axum would otherwise label `text/plain`).
pub(crate) fn provider_error_response(
    status: StatusCode,
    error_code: &str,
    message: Option<&str>,
    provider: Option<&str>,
    retry_after_secs: Option<&'static str>,
) -> axum::response::Response {
    provider_error_response_with_detail(
        status,
        error_code,
        message,
        provider,
        None,
        retry_after_secs,
    )
}

/// [`provider_error_response`] plus `OG-03` §3.4's `provider_message`: the upstream's own
/// `error.message`, already scrubbed and truncated by `ProviderHttpError::from_response`
/// (which refuses 401/403/407, every 5xx and any auth rejection — those arrive here as
/// `None`). It sits beside the gateway's own `message`, never in place of it, and the whole
/// body is scrubbed once more below.
pub(crate) fn provider_error_response_with_detail(
    status: StatusCode,
    error_code: &str,
    message: Option<&str>,
    provider: Option<&str>,
    provider_message: Option<&str>,
    retry_after_secs: Option<&'static str>,
) -> axum::response::Response {
    build_provider_error(
        status,
        error_code,
        message,
        provider,
        provider_message,
        retry_after_secs.map(str::to_owned),
        None,
    )
}

/// `OG-10` §3: the upstream's own `Retry-After`, in whole seconds rounded UP (telling a
/// client "1 s" when the provider said "1.2 s" sends it back to be refused again), for a
/// final upstream failure that carries one — a 429 or a 503 and nothing else. `None`
/// otherwise, so a status that is not about waiting never grows a `Retry-After`.
pub(crate) fn upstream_retry_after_secs(err: &anyhow::Error) -> Option<u64> {
    let http = err.downcast_ref::<crate::providers::ProviderHttpError>()?;
    if !matches!(http.status, 429 | 503) {
        return None;
    }
    let d = http.retry_after?;
    Some(d.as_secs() + u64::from(d.subsec_nanos() > 0))
}

/// [`provider_error_response_with_detail`] for a failure whose upstream said how long to
/// wait (`OG-10`): the `Retry-After` header is the provider's value (`upstream_secs`), and
/// the body carries `retry_after_secs` beside it. With `None` it is the gateway's own
/// `fallback_header` guess and NO body field — a guessed number is not presented as the
/// provider's.
pub(crate) fn provider_error_response_retry(
    status: StatusCode,
    error_code: &str,
    message: Option<&str>,
    provider: Option<&str>,
    provider_message: Option<&str>,
    upstream_secs: Option<u64>,
    fallback_header: Option<&'static str>,
) -> axum::response::Response {
    let (header, body_secs) = match upstream_secs {
        Some(secs) => (Some(secs.to_string()), Some(secs)),
        None => (fallback_header.map(str::to_owned), None),
    };
    build_provider_error(
        status,
        error_code,
        message,
        provider,
        provider_message,
        header,
        body_secs,
    )
}

fn build_provider_error(
    status: StatusCode,
    error_code: &str,
    message: Option<&str>,
    provider: Option<&str>,
    provider_message: Option<&str>,
    retry_after_header: Option<String>,
    retry_after_body_secs: Option<u64>,
) -> axum::response::Response {
    let mut map = serde_json::Map::new();
    map.insert("error".into(), error_code.into());
    if let Some(m) = message {
        map.insert("message".into(), m.into());
    }
    if let Some(p) = provider {
        map.insert("provider".into(), p.into());
    }
    if let Some(pm) = provider_message {
        map.insert("provider_message".into(), pm.into());
    }
    if let Some(secs) = retry_after_body_secs {
        map.insert("retry_after_secs".into(), secs.into());
    }
    let raw = serde_json::to_vec(&serde_json::Value::Object(map))
        .unwrap_or_else(|_| b"{\"error\":\"internal\"}".to_vec());
    let scrubbed = tracelane_shared::redact::scrub(&raw);
    let mut resp = (status, scrubbed).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    if let Some(ra) = retry_after_header
        && let Ok(v) = axum::http::HeaderValue::from_str(&ra)
    {
        resp.headers_mut()
            .insert(axum::http::header::RETRY_AFTER, v);
    }
    crate::kms::retry_after(resp, error_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two failure modes must stay distinct: `NotConfigured` tells the user
    /// to ADD a key, `Unusable` tells them to ROTATE one. Emitting the same code
    /// for both sends half of them the wrong way.
    #[test]
    fn provider_key_failure_modes_carry_different_codes() {
        let not_configured = provider_error_response(
            StatusCode::BAD_REQUEST,
            "provider_not_configured",
            Some("add one in Settings → LLM Providers"),
            Some("openai"),
            None,
        );
        let unusable = provider_error_response(
            StatusCode::BAD_GATEWAY,
            "provider_key_unusable",
            Some("rotate it in Settings → LLM Providers"),
            Some("openai"),
            None,
        );
        assert_eq!(not_configured.status(), StatusCode::BAD_REQUEST);
        assert_eq!(unusable.status(), StatusCode::BAD_GATEWAY);
    }

    /// OG-03 §3.4: the upstream's message rides beside ours as `provider_message`, and the
    /// final scrub still runs over it.
    #[tokio::test]
    async fn provider_message_is_relayed_beside_the_gateway_message_and_scrubbed() {
        let resp = provider_error_response_with_detail(
            StatusCode::BAD_REQUEST,
            "provider_request_rejected",
            Some("the gateway's own words"),
            Some("openai"),
            Some("Unsupported parameter: max_tokens. key sk-proj-abcdefghijklmnopqrstuvwxyz0123"),
            None,
        );
        let body = crate::handler_harness::body_json(resp).await;
        assert_eq!(body["message"], "the gateway's own words");
        let pm = body["provider_message"].as_str().expect("provider_message");
        assert!(pm.starts_with("Unsupported parameter: max_tokens"), "{pm}");
        assert!(
            !pm.contains("sk-proj-"),
            "a key shape must not survive: {pm}"
        );
    }

    /// An unclassified upstream 4xx mirrors the upstream status as a 4xx
    /// (never 502 "provider unavailable", which blamed us for a client-side
    /// failure) and names BOTH candidate causes without claiming to know which.
    #[tokio::test]
    async fn unclassified_4xx_names_both_causes_and_is_not_an_outage() {
        let message = format!(
            "the upstream provider rejected this request with HTTP {}. \
             This is not a Tracelane outage — it is usually either a provider \
             key that is invalid or expired for this account, or a request the \
             provider could not accept (model, parameters, or payload). \
             Verify the key for this provider, then the request itself.",
            400
        );
        let resp = provider_error_response(
            StatusCode::BAD_REQUEST,
            "provider_request_rejected",
            Some(&message),
            Some("xai"),
            None,
        );
        assert!(
            resp.status().is_client_error(),
            "an upstream 4xx must not surface as a 5xx"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains("provider_request_rejected") && s.contains("xai"),
            "got: {s}"
        );
        // Names the upstream status, and both causes — not one of them.
        assert!(s.contains("400"), "must name the upstream status: {s}");
        assert!(s.contains("expired") && s.contains("payload"), "got: {s}");
        // Must NOT assert the key is the problem (that is the parsed path).
        assert!(
            !s.contains("provider_key_rejected"),
            "an unparsed 4xx must not claim the key was rejected: {s}"
        );
    }

    ///  mechanical control: the provider-error response must NEVER emit a
    /// key-shaped string or an upstream auth header, even if a future bug
    /// interpolates a raw upstream body (which echoes the tenant's BYOK key +
    /// `www-authenticate`) into a client-facing field. Asserts the allowlist +
    /// the `scrub` backstop together. A redaction gap here fails CI.
    #[tokio::test]
    async fn provider_error_response_never_leaks_key_or_auth_header() {
        // A poisoned message = a simulated future regression that pipes an
        // upstream error body into the client field. Clearly-fake keys per
        // rules/testing.md, one per BYOK format the gateway must catch.
        let poison = "upstream: Incorrect API key sk-projFAKEtestkeyDONOTUSE0123456789abcdef; \
             AIzaFAKEtestkeyDONOTUSE0123456789abcdef0; xai-FAKEtestkeyDONOTUSE0123456789abcd; \
             AQ.Ab8RN6FAKEtestkeyDONOTUSE0123456789abcdef; tlane_FAKEtestkeyDONOTUSE0123456789; \
             www-authenticate: Bearer sk-FAKEtestkeyDONOTUSE0123456789abcdef; \
             authorization: Bearer FAKEtestjwtDONOTUSE0123456789abcdef";
        let resp = provider_error_response(
            StatusCode::UNAUTHORIZED,
            "provider_key_rejected",
            Some(poison),
            Some("openai"),
            None,
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let s = String::from_utf8_lossy(&bytes);
        // Not one raw credential fragment survives (the value shape is scrubbed).
        assert!(
            !s.contains("FAKEtestkey") && !s.contains("FAKEtestjwt"),
            "provider-error body leaked a key/token: {s}"
        );
        // The upstream auth header value is gone.
        assert!(
            !s.to_lowercase().contains("bearer sk-"),
            "auth header leaked: {s}"
        );
        // The allowlisted fields still render (so the fix didn't break the error).
        assert!(
            s.contains("provider_key_rejected") && s.contains("openai"),
            "got: {s}"
        );
    }
}
