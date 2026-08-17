//! `POST /v1/traces` — the authenticated OTLP write path (`GWY-41`, B-227).
//!
//! ## Why this route exists
//!
//! Until this route, **a Tracelane Cloud customer could not produce a multi-span
//! trace at all.** The gateway emits one root span per request with
//! `parent_span_id: None` (`server.rs`, `build_gateway_span`), and ingest's OTLP
//! receiver is reachable only over SPIFFE mTLS inside the Docker network. So the
//! waterfall, `OBS-10` trace compare and the transcript spine were all built and
//! structurally unreachable: nothing could create the input they render. B-208
//! measured the consequence — 2,400 traces over 13 days, `max(span_count) = 1` —
//! and filed it as a data problem. It was a reachability gap.
//!
//! This is B-227 option (a): bearer auth the gateway already has, feeding the
//! NATS → ingest path that already exists. **ADR-028 is untouched** — ingest's own
//! port, its SPIFFE requirement and its release-build refusal are unchanged, and
//! nothing here talks to ingest except through `tracelane.spans.{tenant_id}`,
//! the subject the gateway has always published its own spans on.
//!
//! ## Where it is mounted, and why not next to the GET
//!
//! `trace_reads::routes()` owns `GET /v1/traces` — the ClickHouse READ surface,
//! with `TraceReadState` and a `CLICKHOUSE_URL` mount gate. This is a WRITE route
//! needing `AppState.nats` and a different gate entirely, so it mounts in
//! `server.rs` with the rest of `AppState`. Axum merges the two because GET and
//! POST are disjoint methods on the same path — a property that is asserted by a
//! test in `server.rs`, not assumed.
//!
//! ## Fail directions
//!
//! **Fail-CLOSED on the security paths:** no credential → 401; a key without the
//! `ingest` scope → 403; a cap exceeded → the whole batch is refused and nothing
//! is published. **Fail-CLOSED on capture too**, which is the unusual choice and
//! the deliberate one: with no NATS client this returns 503, never a silent 200.
//! Accepting spans and dropping them is the #81 failure class, and on an
//! observability product it is the worst possible shape.

use std::time::Duration;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use tracing::instrument;

use tracelane_shared::{
    TenantId,
    otlp::{
        decode::{
            BatchReject, DecodeOutcome, Wire, decode_batch_with_limits, wire_from_content_type,
        },
        limits::{IngestLimits, RejectReason, WARNING_ENFORCEMENT_DATE, record_reject},
    },
};

use crate::server::AppState;

/// The credential header both shipped SDKs send.
///
/// **This is not a second auth path.** `@tracelanedev/sdk@0.2.3` and
/// `tracelane@0.2.3` set exactly one header — `x-tracelane-api-key` — and neither
/// config type exposes a bearer or a headers option. Until now nothing read it
/// (`grep -rn "tracelane-api-key" crates/` was zero hits). A route accepting only
/// `Authorization` would be unusable by every SDK version already published, so
/// the proof would be gated behind an SDK release for no security gain: the value
/// is the same credential and goes to the same validator.
const API_KEY_HEADER: &str = "x-tracelane-api-key";

/// ADR-029 reject reason header — the stable enum string an SDK matches on.
const REJECT_REASON_HEADER: &str = "tracelane-reject-reason";
/// ADR-029 soft-warning header.
const WARNING_HEADER: &str = "tracelane-warning";

/// Max spans in one export.
///
/// A different axis from every byte cap: a million zero-byte spans passes all of
/// them and is still a million NATS publishes. OTel's `BatchSpanProcessor`
/// defaults to 512 spans per export, so this is 4× headroom over what a correctly
/// configured SDK sends.
pub const MAX_SPANS_PER_REQUEST: usize = 2_048;

/// OTel's `BatchSpanProcessor` default export size. The cap must clear it with
/// real headroom or the first thing a customer sees is a 413 on a perfectly
/// normal batch.
const OTEL_DEFAULT_MAX_EXPORT_BATCH: usize = 512;
const _: () = assert!(
    MAX_SPANS_PER_REQUEST >= OTEL_DEFAULT_MAX_EXPORT_BATCH * 4,
    "MAX_SPANS_PER_REQUEST must leave 4x headroom over a default OTel export batch"
);

/// Max serialized bytes for ONE span on the NATS wire.
///
/// **Read from the running server, not assumed:** prod NATS reports
/// `max_payload = 1048576` at `/varz`. ADR-029's per-span cap is 1 MiB of
/// *protobuf*, and the JSON encoding of the same span is larger — so a span that
/// is legal under ADR-029 can still exceed what NATS will accept. Without this
/// check that span is refused by the broker AFTER a 200 has been returned, which
/// is a silent drop. Checked on the encoded bytes, before anything is published.
pub const MAX_NATS_PAYLOAD_BYTES: usize = 1_048_576;

/// Budget for reading the request body off the socket. Bounds a slowloris upload
/// that would otherwise hold a connection open indefinitely.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Budget for the protobuf decode + cap walk.
///
/// The work runs on `spawn_blocking`, so this timeout is real rather than
/// decorative: `prost` decoding is synchronous CPU work, and a `timeout` wrapped
/// around a synchronous call on the async runtime can only fire at an await point
/// that never comes.
const DECODE_TIMEOUT: Duration = Duration::from_secs(5);

/// Extract the bearer credential from either accepted header.
///
/// `Authorization` wins when both are present — the explicit, standard header
/// beats the compatibility one. Returns the raw credential with any `Bearer `
/// prefix intact for `Authorization`, and re-wraps the API-key header into the
/// same shape so exactly one validator sees exactly one format.
fn credential(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Some(v.to_string());
    }
    headers
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| format!("Bearer {v}"))
}

/// Build the ADR-029 reject response: typed status, the stable reason header, and
/// the measured figures.
fn reject_response(reject: BatchReject, tenant: Option<&TenantId>) -> Response {
    record_reject(
        reject.reason,
        tenant.map(|t| tracelane_shared::otlp::limits::workspace_bucket(t.as_uuid())),
    );
    let status =
        StatusCode::from_u16(reject.reason.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut body = serde_json::json!({
        "error": "payload_rejected",
        "reason": reject.reason.label(),
        "limit": reject.limit,
    });
    if reject.reason == RejectReason::UnsupportedContentType {
        // Name what IS accepted. A rejection that only says "no" costs the reader
        // a support round-trip.
        body["message"] = serde_json::json!(
            "set Content-Type to application/x-protobuf (OTLP/protobuf) or application/json (OTLP/JSON)"
        );
        body.as_object_mut().map(|o| o.remove("limit"));
    }
    if let Some(o) = reject.observed {
        body["observed"] = serde_json::json!(o);
    }
    let mut resp = (status, Json(body)).into_response();
    if let Ok(val) = HeaderValue::from_str(reject.reason.label()) {
        resp.headers_mut()
            .insert(HeaderName::from_static(REJECT_REASON_HEADER), val);
    }
    resp
}

fn json_error(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

/// `POST /v1/traces` — accept an OTLP/HTTP protobuf trace export.
///
/// # Errors
/// Every failure is **fail-CLOSED**: nothing is published unless the whole batch
/// passed every gate. See the module docs for the fail-direction rationale.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty, spans = tracing::field::Empty))]
pub async fn ingest_traces_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    // ── 1. Authenticate ────────────────────────────────────────────────────
    let Some(cred) = credential(&headers) else {
        return json_error(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({ "error": "missing credentials" }),
        );
    };
    let claims = match crate::auth::validate_authorization(&cred).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "trace ingest: authentication failed");
            return json_error(
                StatusCode::UNAUTHORIZED,
                serde_json::json!({ "error": "invalid or expired credentials" }),
            );
        }
    };

    // ── 2. Scope gate — before anything expensive, exactly as the chat path ──
    // A `read` key (the shape handed to an external auditor) must not be able to
    // WRITE spans into the workspace it was given to read.
    if !claims.allows_scope(crate::auth::scope::Scope::Ingest) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `ingest` scope — refusing trace export");
        return json_error(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": {
                    "message": "This API key is not scoped to send traces. It needs the `ingest` scope; mint a new key with it in Settings → API Keys.",
                    "type": "insufficient_scope",
                    "required_scope": "ingest",
                }
            }),
        );
    }

    let tenant_id = claims.tenant_id.clone();
    tracing::Span::current().record("tenant_id", tracing::field::display(&tenant_id));

    // ── 3. Rate limit, on the tenant's real plan tier ───────────────────────
    // The same limiter and the same tier resolution the chat path uses. Note it
    // does NOT touch `quota_tracker`: that counter meters billable overage
    // (SET-13), and feeding a telemetry export into a billing counter is a money
    // decision, not a plumbing one.
    let tier = match &state.entitlements {
        Some(cache) => cache.resolved(*tenant_id.as_uuid()).await.rate_limit_tier(),
        None => crate::rate_limiter::RateLimitTier::Free,
    };
    if let crate::rate_limiter::RateLimitDecision::Throttle { retry_after_secs } =
        state.rate_limiter.check(&tenant_id, tier)
    {
        crate::rejection_metrics::registry().record_rate_limited(&tenant_id);
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({
                "error": "rate limit exceeded",
                "retry_after_secs": retry_after_secs,
            }),
        );
    }

    // ── 4. Capture must be live, or say so ──────────────────────────────────
    // Deliberately NOT a 404 when the route is unusable. A 404 reads as "wrong
    // URL" and would send the customer hunting an ingest hostname that does not
    // exist — which is exactly the dead end B-227 was.
    let Some(nats) = state.nats.clone() else {
        crate::otlp_emit::note_span_dropped_no_nats();
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "error": "capture_disabled",
                "message": "This gateway was started without span capture (no NATS_URL), so it cannot accept traces.",
            }),
        );
    };

    let cap = IngestLimits::for_workspace(&());

    // ── 4b. Resolve the WIRE FORMAT before reading a byte of body (B-235) ────
    //
    // Both shipped SDKs are first-class here and they disagree:
    // `tracelane` (Python) exports protobuf, `@tracelanedev/sdk` (TypeScript)
    // exports **JSON**. Shipping protobuf-only meant the TS SDK could not deliver
    // a span to Tracelane at all — Cloud or self-host — and no SDK republish
    // repairs installed copies, so the fix has to live here.
    //
    // An unrecognised or ABSENT Content-Type is refused by NAME. It used to fall
    // through to a protobuf attempt, so a JSON body came back as
    // `failed to decode Protobuf message: unexpected end group tag` — a
    // malformed-body answer to a wrong-format question.
    let wire = match wire_from_content_type(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
    ) {
        Some(w) => w,
        None => {
            return reject_response(
                BatchReject {
                    reason: RejectReason::UnsupportedContentType,
                    limit: 0,
                    observed: None,
                },
                Some(&tenant_id),
            );
        }
    };

    // ── 5. Read the body under a cap and a clock ────────────────────────────
    let read = tokio::time::timeout(
        BODY_READ_TIMEOUT,
        axum::body::to_bytes(body, cap.max_batch_bytes()),
    )
    .await;
    let bytes = match read {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => {
            // `to_bytes` fails on the cap as well as on a broken stream. Report the
            // cap, which is the actionable one.
            return reject_response(
                BatchReject {
                    reason: RejectReason::BatchTooLarge,
                    limit: cap.max_batch_bytes() as u64,
                    observed: None,
                },
                Some(&tenant_id),
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::REQUEST_TIMEOUT,
                serde_json::json!({ "error": "body_read_timeout" }),
            );
        }
    };

    // An OTLP exporter with nothing to send is not an error (`ExportTraceService`
    // permits an empty request); an empty HTTP body is a malformed one.
    if bytes.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "empty body" }),
        );
    }

    // ── 6. Decode + enforce every ADR-029 cap, off the async runtime ────────
    let decode_tenant = tenant_id.clone();
    let decode = tokio::time::timeout(
        DECODE_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            decode_batch_with_limits(&bytes, &decode_tenant, &cap, MAX_SPANS_PER_REQUEST, wire)
        }),
    )
    .await;

    let outcome = match decode {
        Ok(Ok(o)) => o,
        Ok(Err(join_err)) => {
            tracing::error!(error = %join_err, "trace ingest: decode task failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "decode_failed" }),
            );
        }
        Err(_) => {
            tracing::warn!(
                budget_secs = DECODE_TIMEOUT.as_secs(),
                "trace ingest: decode budget exceeded"
            );
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({ "error": "decode_timeout" }),
            );
        }
    };

    let batch = match outcome {
        DecodeOutcome::Ok(b) => b,
        DecodeOutcome::Rejected(r) => return reject_response(r, Some(&tenant_id)),
        DecodeOutcome::Malformed(msg) => {
            tracing::warn!(error = %msg, "trace ingest: OTLP decode failed");
            return json_error(StatusCode::BAD_REQUEST, serde_json::json!({ "error": msg }));
        }
    };

    tracing::Span::current().record("spans", batch.spans.len());

    // ── 7. Serialize everything BEFORE publishing anything ──────────────────
    // All-or-nothing at the size gate. Publishing half a batch and then returning
    // 413 for the rest would leave the customer's trace permanently truncated
    // with no way to tell which half landed.
    let mut payloads: Vec<(String, Vec<u8>)> = Vec::with_capacity(batch.spans.len());
    for span in &batch.spans {
        let payload = match serde_json::to_vec(span) {
            Ok(p) => p,
            Err(err) => {
                tracing::error!(error = %err, "trace ingest: span serialize failed");
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::json!({ "error": "span_serialize_failed" }),
                );
            }
        };
        if payload.len() > MAX_NATS_PAYLOAD_BYTES {
            return reject_response(
                BatchReject {
                    reason: RejectReason::SpanTooLarge,
                    limit: MAX_NATS_PAYLOAD_BYTES as u64,
                    observed: Some(payload.len() as u64),
                },
                Some(&tenant_id),
            );
        }
        payloads.push((crate::otlp_emit::span_subject(span), payload));
    }

    // ── 8. Publish. The subject carries the tenant; ingest re-binds from it ──
    let n_total = payloads.len();
    let mut n_rejected = 0usize;
    for (subject, payload) in payloads {
        if let Err(err) = nats.publish(subject, payload.into()).await {
            crate::otlp_emit::note_span_publish_failed();
            tracing::warn!(error = %err, "trace ingest: span publish failed");
            n_rejected += 1;
        }
    }

    if n_rejected > 0 {
        // OTLP's partial-success shape, matching what ingest's own receiver
        // returns under backpressure. 503 so the SDK retries the batch.
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "partial_success": {
                    "rejected_spans": n_rejected,
                    "error_message": "span publish failed",
                }
            }),
        );
    }

    tracing::debug!(spans = n_total, "OTLP batch accepted");

    let mut resp = (StatusCode::OK, Json(serde_json::json!({}))).into_response();
    if batch.any_warning_band {
        let value = format!("limit-payload-size; enforcement-date={WARNING_ENFORCEMENT_DATE}");
        if let Ok(val) = HeaderValue::from_str(&value) {
            resp.headers_mut()
                .insert(HeaderName::from_static(WARNING_HEADER), val);
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn authorization_is_taken_verbatim() {
        assert_eq!(
            credential(&hm(&[("authorization", "Bearer tlane_abc")])).as_deref(),
            Some("Bearer tlane_abc")
        );
    }

    /// The compatibility case that makes the published SDKs work unchanged.
    #[test]
    fn the_sdk_header_is_rewrapped_into_the_same_shape() {
        assert_eq!(
            credential(&hm(&[("x-tracelane-api-key", "tlane_abc")])).as_deref(),
            Some("Bearer tlane_abc"),
            "the SDK header must reach the SAME validator in the SAME format — one \
             credential in two envelopes, never two auth paths"
        );
    }

    /// Explicit beats compatibility, and it must be deterministic: a request
    /// carrying both must not depend on header ordering for which key is used.
    #[test]
    fn authorization_wins_when_both_are_present() {
        assert_eq!(
            credential(&hm(&[
                ("x-tracelane-api-key", "tlane_from_sdk_header"),
                ("authorization", "Bearer tlane_from_authorization"),
            ]))
            .as_deref(),
            Some("Bearer tlane_from_authorization")
        );
    }

    /// A present-but-empty header is not a credential. Without the emptiness
    /// filter this produces `"Bearer "`, which is a *different* failure than
    /// "missing" and would be reported as an invalid key rather than an absent one.
    #[test]
    fn empty_or_absent_headers_yield_no_credential() {
        assert_eq!(credential(&HeaderMap::new()), None);
        assert_eq!(credential(&hm(&[("authorization", "")])), None);
        assert_eq!(credential(&hm(&[("x-tracelane-api-key", "   ")])), None);
        // An empty Authorization must fall through to the SDK header rather than
        // shadowing it.
        assert_eq!(
            credential(&hm(&[
                ("authorization", ""),
                ("x-tracelane-api-key", "tlane_x")
            ]))
            .as_deref(),
            Some("Bearer tlane_x")
        );
    }

    /// The NATS ceiling must stay at or below what the broker actually accepts.
    /// Prod reports `max_payload = 1048576` at `/varz`; if that is ever raised,
    /// this const may rise with it — but it must never exceed it, because the
    /// failure it prevents is a silent drop after a 200.
    #[test]
    fn nats_payload_ceiling_matches_the_broker_default() {
        assert_eq!(MAX_NATS_PAYLOAD_BYTES, 1_048_576);
    }
}
