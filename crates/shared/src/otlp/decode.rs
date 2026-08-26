//! OTLP protobuf decoder — converts incoming `ExportTraceServiceRequest`
//! payloads into Tracelane's internal `TracelaneSpan` shape.
//!
//! ## Scope
//!
//! Decodes the protobuf wire format (Content-Type
//! `application/x-protobuf`). JSON OTLP support is deliberately
//! out of scope for V1 — every SDK we ship and every OTel
//! collector we expect to peer with supports protobuf, and binary
//! is meaningfully cheaper at ingest scale.
//!
//! ## Tenant identity
//!
//! The TenantId for the produced span is resolved in priority order:
//! 1. **Request extension** (`Extension<TenantId>`) — set by the
//!    SPIFFE mTLS middleware after verifying the peer SVID. This is
//!    the canonical production path.
//! 2. **Resource attribute** `tracelane.tenant_id` — fallback for
//!    plaintext/dev mode where there's no SPIFFE peer. The value
//!    MUST parse as a UUID; non-UUID values are rejected.
//!
//! If neither is available, the entire request is rejected as
//! unauthorized — we will not write spans we can't attribute.
//!
//! ## ID conversion
//!
//! OTLP carries 16-byte trace IDs and 8-byte span IDs. Tracelane
//! uses UUID (16 bytes) for both:
//! - trace_id: direct 16-byte → UUID conversion (`Uuid::from_bytes`).
//! - span_id: zero-padded to 16 bytes (low 8 bytes filled, high 8
//!   bytes zero), then `Uuid::from_bytes`. The original 8-byte ID
//!   is recoverable as the low 64 bits.
//!
//! ## Timestamps
//!
//! OTLP carries `start_time_unix_nano` / `end_time_unix_nano` as
//! `u64`. Tracelane stores `DateTime<Utc>` (microsecond precision via
//! `chrono::DateTime`). Conversion is lossy at the nanosecond level
//! but matches the resolution of every downstream consumer.

use anyhow::{Context as _, Result, bail};
use chrono::{DateTime, TimeZone, Utc};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::trace::v1::Span as OtlpSpan;
use prost::Message;
use uuid::Uuid;

use crate::{
    TenantId, TracelaneSpan,
    span::{SpanAttributes, SpanStatus, SpanStatusCode},
};

/// Resource attribute key used to carry tenant identity in plaintext
/// dev mode. Production deployments use SPIFFE mTLS instead and
/// ignore this attribute.
pub const TRACELANE_TENANT_ID_ATTR: &str = "tracelane.tenant_id";

/// Decode an OTLP protobuf payload into a flat list of `TracelaneSpan`s.
///
/// `peer_tenant` is the SPIFFE-verified `TenantId` from the request
/// extension if present (production path); `None` means we'll attempt
/// to fall back to the resource attribute `tracelane.tenant_id`
/// (plaintext dev path).
///
/// # Errors
///
/// - Protobuf decode failure
/// - Neither peer_tenant nor resource attribute provides a valid
///   tenant_id → returns `Err` (caller should respond 401)
/// - A span carries a malformed trace_id / span_id (wrong byte length)
pub fn decode_otlp_protobuf(
    body: &[u8],
    peer_tenant: Option<&TenantId>,
) -> Result<Vec<TracelaneSpan>> {
    let req = ExportTraceServiceRequest::decode(body).context("OTLP protobuf decode failed")?;
    map_otlp_to_tracelane_spans(req, peer_tenant)
}

/// Map an already-decoded `ExportTraceServiceRequest` to a flat list of
/// `TracelaneSpan`s. Same semantics as [`decode_otlp_protobuf`] but
/// skips the protobuf decode — used by the receiver (`otlp_receiver`)
/// when it needs to walk + mutate the protobuf before mapping (e.g.,
/// for ADR-029 size enforcement and ADR-030 cardinality overflow
/// coercion) without paying a second decode.
pub fn map_otlp_to_tracelane_spans(
    req: ExportTraceServiceRequest,
    peer_tenant: Option<&TenantId>,
) -> Result<Vec<TracelaneSpan>> {
    let mut out = Vec::new();
    for resource_spans in req.resource_spans {
        // Resolve tenant for this ResourceSpans block.
        let resource_attrs = resource_spans
            .resource
            .as_ref()
            .map(|r| r.attributes.as_slice())
            .unwrap_or(&[]);

        let tenant_id = resolve_tenant(peer_tenant, resource_attrs)?;

        for scope_spans in resource_spans.scope_spans {
            for span in scope_spans.spans {
                let mapped = map_span(&tenant_id, span)?;
                out.push(mapped);
            }
        }
    }

    Ok(out)
}

/// Resolve the tenant for a `ResourceSpans` block.
///
/// **Security invariant** (CLAUDE.md): `tenant_id` MUST come from a
/// validated SPIFFE SVID (production) or a JWT claim. The resource-
/// attribute fallback is a dev-only convenience and is hard-gated to
/// debug builds via `#[cfg(debug_assertions)]`. Release binaries that
/// fail to receive a SPIFFE peer return a 401-equivalent error rather
/// than accepting a body-supplied `tracelane.tenant_id` (A1 / R-launch).
fn resolve_tenant(peer_tenant: Option<&TenantId>, resource_attrs: &[KeyValue]) -> Result<TenantId> {
    if let Some(t) = peer_tenant {
        return Ok(t.clone());
    }

    #[cfg(debug_assertions)]
    {
        let attr = resource_attrs
            .iter()
            .find(|kv| kv.key == TRACELANE_TENANT_ID_ATTR)
            .and_then(|kv| kv.value.as_ref())
            .and_then(|av| av.value.as_ref());
        let raw = match attr {
            Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s)) => {
                s.as_str()
            }
            _ => bail!(
                "no SPIFFE peer + no `{TRACELANE_TENANT_ID_ATTR}` resource attribute (debug build)"
            ),
        };
        let uuid = Uuid::parse_str(raw)
            .with_context(|| format!("`{TRACELANE_TENANT_ID_ATTR}` is not a valid UUID"))?;
        Ok(TenantId::from_jwt_claim(uuid))
    }

    #[cfg(not(debug_assertions))]
    {
        // resource_attrs intentionally ignored in release; reject loudly.
        let _ = resource_attrs;
        bail!(
            "no SPIFFE peer attached — release builds require mTLS-authenticated ingest. \
             Configure TRACELANE_SPIRE_SOCKET before deploying."
        );
    }
}

fn map_span(tenant_id: &TenantId, span: OtlpSpan) -> Result<TracelaneSpan> {
    let trace_id =
        otlp_trace_id_to_uuid(&span.trace_id).context("OTLP trace_id is not 16 bytes")?;
    let span_id = otlp_span_id_to_uuid(&span.span_id).context("OTLP span_id is not 8 bytes")?;
    let parent_span_id = if span.parent_span_id.is_empty() {
        None
    } else {
        Some(
            otlp_span_id_to_uuid(&span.parent_span_id)
                .context("OTLP parent_span_id is not 8 bytes")?,
        )
    };

    let start_time =
        nanos_to_utc(span.start_time_unix_nano).context("invalid start_time_unix_nano")?;
    let end_time = if span.end_time_unix_nano == 0 {
        None
    } else {
        Some(nanos_to_utc(span.end_time_unix_nano).context("invalid end_time_unix_nano")?)
    };

    let attributes = build_attributes(&span.attributes);

    let status = match span.status {
        Some(s) => SpanStatus {
            code: match s.code {
                // OTel proto: 0 = Unset, 1 = Ok, 2 = Error
                1 => SpanStatusCode::Ok,
                2 => SpanStatusCode::Error,
                _ => SpanStatusCode::Unset,
            },
            message: if s.message.is_empty() {
                None
            } else {
                Some(s.message)
            },
        },
        None => SpanStatus {
            code: SpanStatusCode::Unset,
            message: None,
        },
    };

    Ok(TracelaneSpan {
        span_id,
        trace_id,
        parent_span_id,
        tenant_id: tenant_id.clone(),
        name: span.name,
        start_time,
        end_time,
        attributes,
        status,
    })
}

/// Convert a 16-byte OTLP trace ID to a UUID.
fn otlp_trace_id_to_uuid(bytes: &[u8]) -> Result<Uuid> {
    if bytes.len() != 16 {
        bail!("OTLP trace_id must be 16 bytes, got {}", bytes.len());
    }
    let arr: [u8; 16] = bytes.try_into().expect("length checked above");
    Ok(Uuid::from_bytes(arr))
}

/// Convert an 8-byte OTLP span ID to a UUID by zero-padding the high
/// 8 bytes. The original 8-byte ID is recoverable as the low 64 bits.
fn otlp_span_id_to_uuid(bytes: &[u8]) -> Result<Uuid> {
    if bytes.len() != 8 {
        bail!("OTLP span_id must be 8 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 16];
    arr[8..].copy_from_slice(bytes);
    Ok(Uuid::from_bytes(arr))
}

fn nanos_to_utc(nanos: u64) -> Result<DateTime<Utc>> {
    let secs = (nanos / 1_000_000_000) as i64;
    let rem_nanos = (nanos % 1_000_000_000) as u32;
    Utc.timestamp_opt(secs, rem_nanos)
        .single()
        .context("unix timestamp out of range")
}

/// Pull the OTel-GenAI-semconv-mapped fields out of the span's
/// attributes vector. Anything not on the curated list is kept in
/// `_extra` (JSON) for forensic visibility but not used by the
/// gateway's hot-path queries.
fn build_attributes(attrs: &[KeyValue]) -> SpanAttributes {
    let mut out = SpanAttributes::default();
    for kv in attrs {
        let Some(av) = &kv.value else { continue };
        match kv.key.as_str() {
            // OTel GenAI semconv — provider identity.
            // Store-side normalization (ADR-032): a legacy adapter emits
            // `gen_ai.system`, a v1.41 adapter emits `gen_ai.provider.name`.
            // Both must land in the canonical `gen_ai_provider_name` column so
            // PP-SCHEMA-EVOLUTION sees identical rows. We keep `gen_ai_system`
            // populated for round-trip back-compat, and back-fill the canonical
            // field only if a v1.41 `gen_ai.provider.name` has not already set it.
            "gen_ai.system" => {
                let v = any_value_string(av);
                out.gen_ai_system = v.clone();
                if out.gen_ai_provider_name.is_none() {
                    out.gen_ai_provider_name = v;
                }
            }
            "gen_ai.provider.name" => out.gen_ai_provider_name = any_value_string(av),
            "gen_ai.request.model" => out.gen_ai_request_model = any_value_string(av),
            "gen_ai.response.model" => out.gen_ai_response_model = any_value_string(av),
            "gen_ai.operation.name" => out.gen_ai_operation_name = any_value_string(av),
            "gen_ai.agent.name" => out.gen_ai_agent_name = any_value_string(av),
            "gen_ai.agent.version" => out.gen_ai_agent_version = any_value_string(av),
            "gen_ai.conversation.id" => out.gen_ai_conversation_id = any_value_string(av),
            "gen_ai.usage.input_tokens" => {
                out.gen_ai_usage_input_tokens = any_value_u32(av);
            }
            "gen_ai.usage.output_tokens" => {
                out.gen_ai_usage_output_tokens = any_value_u32(av);
            }
            // v1.40/v1.41 token + streaming additions
            "gen_ai.usage.cache_read.input_tokens" => {
                out.gen_ai_usage_cache_read_input_tokens = any_value_u32(av);
            }
            "gen_ai.usage.cache_creation.input_tokens" => {
                out.gen_ai_usage_cache_creation_input_tokens = any_value_u32(av);
            }
            "gen_ai.usage.reasoning.output_tokens" => {
                out.gen_ai_usage_reasoning_output_tokens = any_value_u32(av);
            }
            "gen_ai.request.stream" => {
                out.gen_ai_request_stream = any_value_bool(av);
            }
            "gen_ai.response.time_to_first_chunk" => {
                out.gen_ai_response_time_to_first_chunk = any_value_f64(av);
            }
            // Structured message capture (v1.37+, replaces per-message events)
            "gen_ai.system_instructions" => {
                out.gen_ai_system_instructions = any_value_json(av);
            }
            "gen_ai.input.messages" => {
                out.gen_ai_input_messages = any_value_json(av);
            }
            "gen_ai.output.messages" => {
                out.gen_ai_output_messages = any_value_json(av);
            }
            // Tracelane-specific
            "tracelane.predictive.rug_pull_detected" => {
                out.tracelane_predictive_rug_pull_detected = any_value_bool(av);
            }
            "tracelane.predictive.stuck_loop" => {
                out.tracelane_predictive_stuck_loop = any_value_bool(av);
            }
            "tracelane.predictive.captcha_detected" => {
                out.tracelane_predictive_captcha_detected = any_value_bool(av);
            }
            "tracelane.predictive.anomaly_score" => {
                out.tracelane_predictive_anomaly_score = any_value_f32(av);
            }
            "tracelane.aft_id" => {
                // Bounded-taxonomy enforcement (ADR-056 H1): drop an attacker-
                // supplied free-text aft id at the ingest boundary so it never
                // enters SpanAttributes (nor the cross-tenant federation table).
                out.tracelane_aft_id =
                    any_value_string(av).filter(|s| crate::aft::is_valid_aft_id(s));
            }
            "tracelane.mcp.tool_hash" => {
                out.tracelane_mcp_tool_hash = any_value_string(av);
            }
            "tracelane.mcp.server_url" => {
                out.tracelane_mcp_server_url = any_value_string(av);
            }
            "tracelane.kya.agent_id" => {
                out.tracelane_kya_agent_id = any_value_string(av);
            }
            "tracelane.business_reference" => {
                // Customer-supplied free text — length-bound at the ingest
                // boundary (same posture as the aft_id taxonomy guard above) so
                // an oversized value never enters a span or the export.
                out.tracelane_business_reference = any_value_string(av)
                    .as_deref()
                    .and_then(crate::span::bounded_business_reference);
            }
            // Legacy `gen_ai.openai.*` → canonical `openai.*` (v1.37 rename,
            // ADR-032). Preserved in the `extra` blob under the renamed key so
            // provider-specific detail is not lost. Already-`openai.*` keys
            // pass through unchanged below.
            k if k.starts_with("gen_ai.openai.") => {
                if let Some(v) = any_value_string(av) {
                    let renamed = k.replacen("gen_ai.openai.", "openai.", 1);
                    out.extra.insert(renamed, serde_json::Value::String(v));
                }
            }
            k if k.starts_with("openai.") => {
                if let Some(v) = any_value_string(av) {
                    out.extra
                        .insert(k.to_string(), serde_json::Value::String(v));
                }
            }
            _ => {
                // Unmapped attribute — ignored for V1. A future
                // schema can stash these in `_extra` JSON.
            }
        }
    }
    out
}

fn any_value_string(av: &AnyValue) -> Option<String> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s)) => {
            Some(s.clone())
        }
        _ => None,
    }
}

fn any_value_u32(av: &AnyValue) -> Option<u32> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue(n)) => {
            if *n >= 0 && *n <= u32::MAX as i64 {
                Some(*n as u32)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn any_value_f32(av: &AnyValue) -> Option<f32> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::DoubleValue(d)) => {
            Some(*d as f32)
        }
        _ => None,
    }
}

fn any_value_bool(av: &AnyValue) -> Option<bool> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::BoolValue(b)) => Some(*b),
        _ => None,
    }
}

fn any_value_f64(av: &AnyValue) -> Option<f64> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::DoubleValue(d)) => Some(*d),
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue(n)) => {
            Some(*n as f64)
        }
        _ => None,
    }
}

/// Decode a structured-message attribute (`gen_ai.input.messages` etc.). Adapters
/// emit these as a JSON-serialized string; parse it when valid, else keep the
/// raw string so no content is lost.
fn any_value_json(av: &AnyValue) -> Option<serde_json::Value> {
    let s = any_value_string(av)?;
    Some(serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s)))
}

// ── GWY-41: the one decode-and-enforce entry point for an UNTRUSTED caller ──

/// The OTLP wire format a body claims to be in (B-235).
///
/// **Both are first-class.** `packages/sdk-python` exports protobuf
/// (`opentelemetry-exporter-otlp-proto-http`) and `packages/sdk-typescript`
/// exports **JSON** (`@opentelemetry/exporter-trace-otlp-http` — the `-proto`
/// variant is the protobuf one). Supporting only protobuf meant the TypeScript
/// SDK could not deliver a span to Tracelane at all, Cloud or self-host, and no
/// SDK republish repairs the copies customers already have installed. The fix
/// therefore belongs on the SERVER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    Protobuf,
    Json,
}

/// Resolve a `Content-Type` to a wire format. `None` means "cannot decode this".
///
/// **A missing header is `None`, not a protobuf guess.** Guessing is what
/// shipped: an OTLP/JSON body fell through to `prost` and came back as
/// `failed to decode Protobuf message: unexpected end group tag`, which sends
/// the SDK author to debug their spans instead of their content type. OTLP/HTTP
/// requires the header; absence is a client bug and is named as one.
///
/// Parameters are stripped (`application/json; charset=utf-8`) and the match is
/// case-insensitive, per RFC 9110 — a media type is not case-sensitive and a
/// charset parameter is not a different format.
#[must_use]
pub fn wire_from_content_type(ct: Option<&str>) -> Option<Wire> {
    let base = ct?.split(';').next()?.trim().to_ascii_lowercase();
    match base.as_str() {
        // `application/protobuf` is the RFC-registered spelling; OTLP and every
        // exporter we have seen send `application/x-protobuf`. Accept both, plus
        // the octet-stream some proxies rewrite to.
        "application/x-protobuf" | "application/protobuf" | "application/octet-stream" => {
            Some(Wire::Protobuf)
        }
        "application/json" => Some(Wire::Json),
        _ => None,
    }
}

/// A refused batch: which cap, its value, and what was actually observed.
///
/// Carries the observed figure because "too large" without a number is
/// unactionable — the SDK author needs to know whether they are 10% or 100× over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchReject {
    pub reason: crate::otlp::limits::RejectReason,
    pub limit: u64,
    pub observed: Option<u64>,
}

/// The outcome of [`decode_batch_with_limits`].
#[derive(Debug)]
pub struct DecodedBatch {
    pub spans: Vec<TracelaneSpan>,
    /// True when any span exceeded `max_span_bytes / 2` — the caller attaches
    /// the ADR-029 soft-warning header.
    pub any_warning_band: bool,
}

/// Decode an OTLP protobuf body and enforce every ADR-029 cap, for a caller
/// whose payload is UNTRUSTED.
///
/// **Why this exists rather than each caller writing the loop.** `GWY-41` gave
/// OTLP a second entry point (the gateway's `POST /v1/traces`, B-227). Sharing
/// only the decoder would still leave two copies of the *enforcement order*, and
/// the order is load-bearing: pre-decode size before decode (so a 10 MiB dump
/// never allocates a protobuf struct), count before per-span walk, and
/// `TooManyAttributes` before `AttributeTooLarge` (so 5 000 empty attributes
/// report the count, not 5 000 stacked size errors).
///
/// Ingest's mTLS receiver deliberately does NOT call this: it must mutate
/// attribute keys in the same walk for the ADR-030 cardinality cap, which needs
/// a per-workspace HLL this crate does not carry. It calls the same primitives
/// (`check_payload_pre_decode`, `check_span_post_decode`,
/// [`map_otlp_to_tracelane_spans`]) in its own walk.
///
/// `max_spans` is the per-request span-count cap. It is a different axis from
/// every byte cap: a million zero-byte spans passes all of them.
///
/// `tenant` is a VALIDATED identity. It is passed as `peer_tenant`, so
/// [`resolve_tenant`] returns it and the body-supplied
/// `tracelane.tenant_id` resource attribute is never consulted.
///
/// # Errors
/// `Err(BatchReject)` when any cap is exceeded — **fail-CLOSED**, the whole
/// batch is refused and nothing is emitted, so a caller can never publish a
/// partial batch it has already reported as rejected. Returns
/// `Err(anyhow)`-shaped decode failures via [`DecodeOutcome::Malformed`].
pub fn decode_batch_with_limits(
    body: &[u8],
    tenant: &TenantId,
    cap: &crate::otlp::limits::IngestLimits,
    max_spans: usize,
    wire: Wire,
) -> DecodeOutcome {
    use crate::otlp::limits::{RejectReason, check_payload_pre_decode, check_span_post_decode};

    if let Err(reason) = check_payload_pre_decode(body.len(), cap) {
        return DecodeOutcome::Rejected(BatchReject {
            reason,
            limit: cap.max_batch_bytes() as u64,
            observed: Some(body.len() as u64),
        });
    }

    // THE ONLY PLACE THE TWO WIRES DIVERGE. Everything after this — the count
    // cap, the ADR-029 per-span walk, the tenant seam, the mapping — is the same
    // code on the same `ExportTraceServiceRequest`, which is what makes "a JSON
    // batch and a protobuf batch store byte-identical spans" a property of the
    // structure rather than a coincidence to be re-tested.
    //
    // Note the size cap stays honest across wires: `check_span_post_decode` sizes
    // a span by `prost::Message::encoded_len()`, the PROTOBUF encoding of the
    // decoded struct. So a JSON body is capped on the same basis as a protobuf
    // one and cannot buy extra headroom by being verbose on the wire.
    let req = match wire {
        Wire::Protobuf => match ExportTraceServiceRequest::decode(body) {
            Ok(r) => r,
            Err(err) => return DecodeOutcome::Malformed(format!("protobuf: {err}")),
        },
        Wire::Json => match serde_json::from_slice::<ExportTraceServiceRequest>(body) {
            Ok(r) => r,
            Err(err) => return DecodeOutcome::Malformed(format!("json: {err}")),
        },
    };

    // Count BEFORE the per-span walk: refusing a million-span batch should not
    // first cost a million `encoded_len` calls.
    let n_spans: usize = req
        .resource_spans
        .iter()
        .flat_map(|rs| rs.scope_spans.iter())
        .map(|ss| ss.spans.len())
        .sum();
    if n_spans > max_spans {
        return DecodeOutcome::Rejected(BatchReject {
            reason: RejectReason::TooManySpans,
            limit: max_spans as u64,
            observed: Some(n_spans as u64),
        });
    }

    let mut any_warning_band = false;
    for rs in &req.resource_spans {
        for ss in &rs.scope_spans {
            for span in &ss.spans {
                match check_span_post_decode(span, cap) {
                    Ok(post) => any_warning_band |= post.in_warning_band,
                    Err(reason) => {
                        let (limit, observed) = match reason {
                            RejectReason::TooManyAttributes => (
                                cap.max_attributes_per_span as u64,
                                span.attributes.len() as u64,
                            ),
                            RejectReason::AttributeTooLarge => (
                                cap.max_attribute_value_bytes as u64,
                                span.encoded_len() as u64,
                            ),
                            RejectReason::SpanTooLarge => {
                                (cap.max_span_bytes as u64, span.encoded_len() as u64)
                            }
                            RejectReason::BatchTooLarge => {
                                (cap.max_batch_bytes() as u64, body.len() as u64)
                            }
                            RejectReason::TooManySpans => (max_spans as u64, n_spans as u64),
                            // Unreachable from the per-span walk: the content type is
                            // resolved BEFORE any body is parsed. Enumerated rather than
                            // `_ =>` so the next variant is a compile error here.
                            RejectReason::UnsupportedContentType => (0, 0),
                        };
                        return DecodeOutcome::Rejected(BatchReject {
                            reason,
                            limit,
                            observed: Some(observed),
                        });
                    }
                }
            }
        }
    }

    match map_otlp_to_tracelane_spans(req, Some(tenant)) {
        Ok(spans) => DecodeOutcome::Ok(DecodedBatch {
            spans,
            any_warning_band,
        }),
        Err(err) => DecodeOutcome::Malformed(err.to_string()),
    }
}

/// Three outcomes, kept distinct because they map to three different HTTP
/// statuses and a caller that collapses them tells the SDK the wrong thing to do.
#[derive(Debug)]
pub enum DecodeOutcome {
    Ok(DecodedBatch),
    /// A cap was exceeded — 413 or 400 per `RejectReason::http_status`.
    Rejected(BatchReject),
    /// The bytes are not a valid `ExportTraceServiceRequest`, or a span carried a
    /// malformed id / timestamp — 400. Retrying the same body cannot help.
    Malformed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue as ProtoAnyValue, KeyValue as ProtoKeyValue, any_value::Value as ProtoValue,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::{
        ResourceSpans, ScopeSpans, Span as ProtoSpan, Status as ProtoStatus,
    };

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap())
    }

    fn sample_span() -> ProtoSpan {
        ProtoSpan {
            trace_id: vec![1u8; 16],
            span_id: vec![2u8; 8],
            parent_span_id: vec![3u8; 8],
            name: "chat".into(),
            start_time_unix_nano: 1_700_000_000_000_000_000,
            end_time_unix_nano: 1_700_000_001_000_000_000,
            attributes: vec![
                ProtoKeyValue {
                    key: "gen_ai.system".into(),
                    value: Some(ProtoAnyValue {
                        value: Some(ProtoValue::StringValue("openai".into())),
                    }),
                },
                ProtoKeyValue {
                    key: "gen_ai.usage.input_tokens".into(),
                    value: Some(ProtoAnyValue {
                        value: Some(ProtoValue::IntValue(42)),
                    }),
                },
            ],
            status: Some(ProtoStatus {
                code: 1,
                message: "ok".into(),
            }),
            ..Default::default()
        }
    }

    fn wrap_in_request(span: ProtoSpan, resource_attrs: Vec<ProtoKeyValue>) -> Vec<u8> {
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: resource_attrs,
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![span],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        req.encode_to_vec()
    }

    // ── GWY-41: decode_batch_with_limits — every cap, both sides ────────────
    //
    // Each cap is asserted to PASS just under it and BLOCK just over it. A test
    // that only shows the block cannot tell "the cap fired" from "this input was
    // never going to work", which is how a cap that rejects everything ships
    // looking correct.

    fn batch(n_spans: usize, mutate: impl Fn(usize, &mut ProtoSpan)) -> Vec<u8> {
        let spans: Vec<ProtoSpan> = (0..n_spans)
            .map(|i| {
                let mut sp = sample_span();
                // Distinct span ids so the batch is a realistic export, not n copies.
                sp.span_id = (i as u64 + 1).to_be_bytes().to_vec();
                mutate(i, &mut sp);
                sp
            })
            .collect();
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    spans,
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    fn caps() -> crate::otlp::limits::IngestLimits {
        crate::otlp::limits::IngestLimits::default()
    }

    // ── B-235: OTLP/JSON is a first-class wire ──────────────────────────────

    /// THE PROPERTY THAT MATTERS: the same batch on either wire stores the same
    /// spans, byte for byte. "Byte for byte" is measured on the JSON that
    /// `otlp_emit::publish_span` puts on NATS — the actual stored form — not on a
    /// field-by-field comparison that could pass while a field is dropped.
    #[test]
    fn json_and_protobuf_bodies_store_byte_identical_spans() {
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    spans: vec![sample_span()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let pb = req.encode_to_vec();
        let js = serde_json::to_vec(&req).expect("serialize as OTLP/JSON");

        // Sanity: they really are different bytes on the wire.
        assert_ne!(pb, js);
        assert_eq!(js[0], b'{', "the JSON body must actually be JSON");

        let from_pb = match decode_batch_with_limits(&pb, &tenant(), &caps(), 2_048, Wire::Protobuf)
        {
            DecodeOutcome::Ok(b) => b.spans,
            other => panic!("protobuf: {other:?}"),
        };
        let from_js = match decode_batch_with_limits(&js, &tenant(), &caps(), 2_048, Wire::Json) {
            DecodeOutcome::Ok(b) => b.spans,
            other => panic!("json: {other:?}"),
        };

        assert_eq!(from_pb.len(), 1);
        assert_eq!(from_js.len(), 1);
        assert_eq!(
            serde_json::to_vec(&from_pb).unwrap(),
            serde_json::to_vec(&from_js).unwrap(),
            "the two wires must store the SAME span — this is the whole claim"
        );
    }

    /// The OTLP/JSON wire encodes ids as HEX STRINGS. If that were mishandled the
    /// span would still decode and would land under the WRONG trace — a silent
    /// corruption, not an error. Asserted explicitly against the protobuf ids.
    #[test]
    fn json_hex_ids_round_trip_to_the_same_trace_and_parent() {
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    spans: vec![sample_span()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let js = serde_json::to_vec(&req).unwrap();
        let text = String::from_utf8(js.clone()).unwrap();
        assert!(
            text.contains("\"traceId\""),
            "OTLP/JSON uses camelCase traceId"
        );
        assert!(
            text.contains("0101010101010101"),
            "OTLP/JSON must encode ids as HEX, got: {}",
            &text[..text.len().min(200)]
        );

        let a = match decode_batch_with_limits(
            &req.encode_to_vec(),
            &tenant(),
            &caps(),
            2_048,
            Wire::Protobuf,
        ) {
            DecodeOutcome::Ok(b) => b.spans,
            o => panic!("{o:?}"),
        };
        let b = match decode_batch_with_limits(&js, &tenant(), &caps(), 2_048, Wire::Json) {
            DecodeOutcome::Ok(x) => x.spans,
            o => panic!("{o:?}"),
        };
        assert_eq!(
            a[0].trace_id, b[0].trace_id,
            "trace id differs across wires"
        );
        assert_eq!(a[0].span_id, b[0].span_id, "span id differs across wires");
        assert_eq!(
            a[0].parent_span_id, b[0].parent_span_id,
            "parent linkage differs across wires — the trace TREE would differ"
        );
    }

    /// A MISLABELLED body must fail as a decode error for the wire it CLAIMED,
    /// never fall through to the other one. The message names the wire so the
    /// reader is sent to their Content-Type, not to their span data.
    #[test]
    fn a_mislabelled_body_fails_as_the_wire_it_claimed() {
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    spans: vec![sample_span()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let pb = req.encode_to_vec();
        let js = serde_json::to_vec(&req).unwrap();

        match decode_batch_with_limits(&pb, &tenant(), &caps(), 2_048, Wire::Json) {
            DecodeOutcome::Malformed(m) => assert!(m.starts_with("json:"), "got {m}"),
            o => panic!("protobuf bytes labelled JSON must fail as JSON, got {o:?}"),
        }
        match decode_batch_with_limits(&js, &tenant(), &caps(), 2_048, Wire::Protobuf) {
            DecodeOutcome::Malformed(m) => assert!(m.starts_with("protobuf:"), "got {m}"),
            o => panic!("JSON bytes labelled protobuf must fail as protobuf, got {o:?}"),
        }
    }

    /// Content-Type resolution, including the case that caused B-235: an
    /// unrecognised or ABSENT header must be `None` — never a protobuf guess.
    #[test]
    fn content_type_resolution_never_guesses() {
        for (ct, want) in [
            (Some("application/x-protobuf"), Some(Wire::Protobuf)),
            (Some("application/protobuf"), Some(Wire::Protobuf)),
            (Some("application/octet-stream"), Some(Wire::Protobuf)),
            (Some("application/json"), Some(Wire::Json)),
            (Some("application/json; charset=utf-8"), Some(Wire::Json)),
            (Some("APPLICATION/JSON"), Some(Wire::Json)),
            (Some("  application/json  "), Some(Wire::Json)),
            (Some("text/plain"), None),
            (Some("application/x-www-form-urlencoded"), None),
            (Some(""), None),
            (None, None),
        ] {
            assert_eq!(wire_from_content_type(ct), want, "content-type {ct:?}");
        }
    }

    #[test]
    fn a_normal_batch_decodes_and_keeps_parent_linkage() {
        // The B-227 property in one assertion: a batch carrying parent ids must
        // come out the other side with parent linkage intact, or the waterfall
        // renders a flat list no matter how many spans arrive.
        let out = decode_batch_with_limits(
            &batch(3, |_, _| {}),
            &tenant(),
            &caps(),
            2_048,
            Wire::Protobuf,
        );
        let DecodeOutcome::Ok(b) = out else {
            panic!("expected Ok, got {out:?}")
        };
        assert_eq!(b.spans.len(), 3);
        assert!(!b.any_warning_band);
        for sp in &b.spans {
            assert!(
                sp.parent_span_id.is_some(),
                "parent_span_id must survive the decode — it is the whole point"
            );
            assert_eq!(sp.tenant_id, tenant());
        }
    }

    #[test]
    fn span_count_cap_passes_at_the_cap_and_blocks_one_over() {
        let cap = 4usize;
        assert!(
            matches!(
                decode_batch_with_limits(
                    &batch(cap, |_, _| {}),
                    &tenant(),
                    &caps(),
                    cap,
                    Wire::Protobuf
                ),
                DecodeOutcome::Ok(_)
            ),
            "exactly at the cap must be ACCEPTED"
        );
        let over = decode_batch_with_limits(
            &batch(cap + 1, |_, _| {}),
            &tenant(),
            &caps(),
            cap,
            Wire::Protobuf,
        );
        let DecodeOutcome::Rejected(r) = over else {
            panic!("expected Rejected, got {over:?}")
        };
        assert_eq!(r.reason, crate::otlp::limits::RejectReason::TooManySpans);
        assert_eq!(r.limit, cap as u64);
        assert_eq!(
            r.observed,
            Some(cap as u64 + 1),
            "the observed count must be the real one — 'too many' with no number is unactionable"
        );
    }

    /// The count cap is a DIFFERENT axis from every byte cap. This batch is tiny
    /// in bytes and still refused, which is the property that matters: a flood of
    /// empty spans is a flood of NATS publishes.
    #[test]
    fn the_count_cap_fires_on_a_batch_that_is_small_in_bytes() {
        let body = batch(50, |_, sp| {
            sp.attributes.clear();
            sp.status = None;
            sp.name.clear();
        });
        assert!(
            body.len() < caps().max_batch_bytes(),
            "this batch must be well under the BYTE cap or the test proves nothing"
        );
        assert!(matches!(
            decode_batch_with_limits(&body, &tenant(), &caps(), 10, Wire::Protobuf),
            DecodeOutcome::Rejected(BatchReject {
                reason: crate::otlp::limits::RejectReason::TooManySpans,
                ..
            })
        ));
    }

    #[test]
    fn attribute_count_cap_passes_at_the_cap_and_blocks_one_over() {
        let c = caps();
        let fill = |n: usize| {
            batch(1, move |_, sp| {
                sp.attributes = (0..n)
                    .map(|i| ProtoKeyValue {
                        key: format!("k{i}"),
                        value: Some(ProtoAnyValue {
                            value: Some(ProtoValue::IntValue(1)),
                        }),
                    })
                    .collect();
            })
        };
        assert!(matches!(
            decode_batch_with_limits(
                &fill(c.max_attributes_per_span),
                &tenant(),
                &c,
                2_048,
                Wire::Protobuf
            ),
            DecodeOutcome::Ok(_)
        ));
        let over = decode_batch_with_limits(
            &fill(c.max_attributes_per_span + 1),
            &tenant(),
            &c,
            2_048,
            Wire::Protobuf,
        );
        let DecodeOutcome::Rejected(r) = over else {
            panic!("expected Rejected, got {over:?}")
        };
        assert_eq!(
            r.reason,
            crate::otlp::limits::RejectReason::TooManyAttributes
        );
        assert_eq!(r.limit, c.max_attributes_per_span as u64);
        assert_eq!(r.observed, Some(c.max_attributes_per_span as u64 + 1));
    }

    #[test]
    fn attribute_value_cap_blocks_and_reports_400_not_413() {
        let c = caps();
        let body = batch(1, |_, sp| {
            sp.attributes = vec![ProtoKeyValue {
                key: "big".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::StringValue(
                        "x".repeat(c.max_attribute_value_bytes + 1),
                    )),
                }),
            }];
        });
        let out = decode_batch_with_limits(&body, &tenant(), &c, 2_048, Wire::Protobuf);
        let DecodeOutcome::Rejected(r) = out else {
            panic!("expected Rejected, got {out:?}")
        };
        assert_eq!(
            r.reason,
            crate::otlp::limits::RejectReason::AttributeTooLarge
        );
        // 400, not 413: the span SHAPE is wrong, so splitting the batch will not
        // help and the SDK must not be told to retry smaller.
        assert_eq!(r.reason.http_status(), 400);
    }

    #[test]
    fn pre_decode_body_cap_blocks_without_decoding() {
        let c = caps();
        // Not valid protobuf at all — if this returns BatchTooLarge rather than
        // Malformed, the size check demonstrably ran BEFORE the decode.
        let body = vec![0xFFu8; c.max_batch_bytes() + 1];
        let out = decode_batch_with_limits(&body, &tenant(), &c, 2_048, Wire::Protobuf);
        let DecodeOutcome::Rejected(r) = out else {
            panic!("expected Rejected, got {out:?}")
        };
        assert_eq!(r.reason, crate::otlp::limits::RejectReason::BatchTooLarge);
        assert_eq!(r.observed, Some(body.len() as u64));
    }

    #[test]
    fn garbage_bytes_are_malformed_not_rejected() {
        // Distinct from a cap breach: 400 with a decode message, and no counter
        // moves. Collapsing the two would tell the SDK to split a batch that is
        // not too big, it is not a batch.
        let out = decode_batch_with_limits(
            b"not-a-protobuf-at-all",
            &tenant(),
            &caps(),
            2_048,
            Wire::Protobuf,
        );
        assert!(matches!(out, DecodeOutcome::Malformed(_)), "got {out:?}");
    }

    /// THE TENANT SEAM (CLAUDE.md #3/#4). A hostile body naming another tenant
    /// must be ignored in favour of the validated identity the caller passed.
    #[test]
    fn a_body_supplied_tenant_id_never_overrides_the_validated_one() {
        let hostile = Uuid::parse_str("99999999-9999-4999-8999-999999999999").unwrap();
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![ProtoKeyValue {
                        key: TRACELANE_TENANT_ID_ATTR.into(),
                        value: Some(ProtoAnyValue {
                            value: Some(ProtoValue::StringValue(hostile.to_string())),
                        }),
                    }],
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    spans: vec![sample_span()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec();

        let out = decode_batch_with_limits(&req, &tenant(), &caps(), 2_048, Wire::Protobuf);
        let DecodeOutcome::Ok(b) = out else {
            panic!("expected Ok, got {out:?}")
        };
        assert_eq!(
            b.spans[0].tenant_id,
            tenant(),
            "the resource attribute must be ignored when a validated tenant is supplied"
        );
        assert_ne!(*b.spans[0].tenant_id.as_uuid(), hostile);
    }

    /// An exporter with nothing to send is not an error.
    #[test]
    fn an_empty_export_is_accepted_and_publishes_nothing() {
        let body = ExportTraceServiceRequest {
            resource_spans: vec![],
        }
        .encode_to_vec();
        let out = decode_batch_with_limits(&body, &tenant(), &caps(), 2_048, Wire::Protobuf);
        let DecodeOutcome::Ok(b) = out else {
            panic!("expected Ok, got {out:?}")
        };
        assert!(b.spans.is_empty());
    }

    /// ADR-029 soft-warning band: accepted, but the caller must be told.
    #[test]
    fn a_span_over_half_the_size_cap_sets_the_warning_band() {
        let c = caps();
        let body = batch(1, |_, sp| {
            sp.attributes = vec![ProtoKeyValue {
                key: "payload".into(),
                value: Some(ProtoAnyValue {
                    // Under the per-attribute cap, but enough copies to push the
                    // SPAN over half its own cap.
                    value: Some(ProtoValue::StringValue(
                        "x".repeat(c.max_attribute_value_bytes),
                    )),
                }),
            }]
            .into_iter()
            .cycle()
            .take(20)
            .enumerate()
            .map(|(i, mut kv)| {
                kv.key = format!("payload{i}");
                kv
            })
            .collect();
        });
        let out = decode_batch_with_limits(&body, &tenant(), &c, 2_048, Wire::Protobuf);
        let DecodeOutcome::Ok(b) = out else {
            panic!("expected Ok, got {out:?}")
        };
        assert!(
            b.any_warning_band,
            "a span above max_span_bytes/2 must raise the soft-warning band"
        );
    }

    #[test]
    fn decodes_span_with_peer_tenant() {
        let body = wrap_in_request(sample_span(), vec![]);
        let spans = decode_otlp_protobuf(&body, Some(&tenant())).unwrap();
        assert_eq!(spans.len(), 1);
        let s = &spans[0];
        assert_eq!(s.name, "chat");
        assert_eq!(s.tenant_id, tenant());
        assert_eq!(s.attributes.gen_ai_system.as_deref(), Some("openai"));
        assert_eq!(s.attributes.gen_ai_usage_input_tokens, Some(42));
    }

    /// DEBUG-ONLY: the resource-attribute tenant fallback is a dev convenience
    /// hard-gated to `#[cfg(debug_assertions)]`. `cargo test` runs in debug, so
    /// this asserts the debug acceptance; the release rejection is asserted by
    /// `release_build_rejects_resource_attribute_tenant_fallback` under
    /// `cargo test --release`. Gating this to debug keeps the crate's test suite
    /// green in BOTH profiles (F-1).
    #[cfg(debug_assertions)]
    #[test]
    fn decodes_span_with_resource_attribute_fallback() {
        let body = wrap_in_request(
            sample_span(),
            vec![ProtoKeyValue {
                key: TRACELANE_TENANT_ID_ATTR.into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::StringValue(
                        "11111111-2222-3333-4444-555555555555".into(),
                    )),
                }),
            }],
        );
        let spans = decode_otlp_protobuf(&body, None).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].tenant_id, tenant());
    }

    ///  F-1 — the RELEASE tenant-isolation guarantee, exercised only under
    /// `cargo test --release`.
    ///
    /// In a release build (`debug_assertions` OFF) `resolve_tenant`'s
    /// `#[cfg(not(debug_assertions))]` arm HARD-REJECTS the resource-attribute
    /// fallback: a body-supplied `tracelane.tenant_id` with no SPIFFE peer must
    /// NEVER be accepted (a body value is not a validated identity — CLAUDE.md
    /// tenant-isolation invariant). `cargo test` compiles with `cfg(test)`,
    /// which implies `debug_assertions`, so the normal debug suite can never
    /// reach this branch — it had ZERO coverage until this test + the CI
    /// `--release` job (`.github/workflows/ci.yml` → `ingest-release-tenant-guard`).
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_rejects_resource_attribute_tenant_fallback() {
        // A perfectly-valid UUID in the body must STILL be refused with no peer.
        let body = wrap_in_request(
            sample_span(),
            vec![ProtoKeyValue {
                key: TRACELANE_TENANT_ID_ATTR.into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::StringValue(
                        "11111111-2222-3333-4444-555555555555".into(),
                    )),
                }),
            }],
        );
        let err = decode_otlp_protobuf(&body, None)
            .expect_err("release builds must reject a body-supplied tenant with no SPIFFE peer");
        let msg = err.to_string();
        assert!(
            msg.contains("no SPIFFE peer") || msg.contains("mTLS-authenticated"),
            "expected the release mTLS-required rejection, got: {msg}"
        );

        // Scope check: the rejection is confined to the fallback — a
        // SPIFFE-verified peer still decodes normally in release.
        let spans = decode_otlp_protobuf(&wrap_in_request(sample_span(), vec![]), Some(&tenant()))
            .expect("a SPIFFE-verified peer must still decode in a release build");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].tenant_id, tenant());
    }

    #[test]
    fn peer_tenant_wins_over_resource_attribute() {
        // Resource attribute would say tenant A; peer SVID says tenant B.
        // Peer wins.
        let resource_tenant_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let body = wrap_in_request(
            sample_span(),
            vec![ProtoKeyValue {
                key: TRACELANE_TENANT_ID_ATTR.into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::StringValue(resource_tenant_a.into())),
                }),
            }],
        );
        let spans = decode_otlp_protobuf(&body, Some(&tenant())).unwrap();
        assert_eq!(spans[0].tenant_id, tenant());
        assert_ne!(
            spans[0].tenant_id.as_uuid().to_string(),
            resource_tenant_a,
            "peer SVID must override resource attribute"
        );
    }

    #[test]
    fn rejects_without_any_tenant_source() {
        let body = wrap_in_request(sample_span(), vec![]);
        let result = decode_otlp_protobuf(&body, None);
        assert!(result.is_err(), "no peer + no resource attr must fail");
    }

    #[test]
    fn rejects_malformed_resource_tenant_uuid() {
        let body = wrap_in_request(
            sample_span(),
            vec![ProtoKeyValue {
                key: TRACELANE_TENANT_ID_ATTR.into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::StringValue("not-a-uuid".into())),
                }),
            }],
        );
        let result = decode_otlp_protobuf(&body, None);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_malformed_protobuf() {
        let body = b"this is not protobuf";
        let result = decode_otlp_protobuf(body, Some(&tenant()));
        assert!(result.is_err());
    }

    #[test]
    fn span_id_zero_pads_to_uuid_low_bytes() {
        let body = wrap_in_request(sample_span(), vec![]);
        let spans = decode_otlp_protobuf(&body, Some(&tenant())).unwrap();
        let span_id_bytes = spans[0].span_id.as_bytes();
        // High 8 bytes zero, low 8 bytes are 0x02 (from the sample span).
        assert_eq!(&span_id_bytes[..8], &[0u8; 8]);
        assert_eq!(&span_id_bytes[8..], &[2u8; 8]);
    }

    #[test]
    fn empty_parent_span_id_is_none() {
        let mut span = sample_span();
        span.parent_span_id = vec![];
        let body = wrap_in_request(span, vec![]);
        let spans = decode_otlp_protobuf(&body, Some(&tenant())).unwrap();
        assert!(spans[0].parent_span_id.is_none());
    }

    #[test]
    fn status_maps_otel_codes_to_tracelane() {
        for (otel_code, expected) in [
            (0, SpanStatusCode::Unset),
            (1, SpanStatusCode::Ok),
            (2, SpanStatusCode::Error),
            (99, SpanStatusCode::Unset), // unknown codes → Unset
        ] {
            let mut span = sample_span();
            span.status = Some(ProtoStatus {
                code: otel_code,
                message: String::new(),
            });
            let body = wrap_in_request(span, vec![]);
            let spans = decode_otlp_protobuf(&body, Some(&tenant())).unwrap();
            assert_eq!(spans[0].status.code, expected, "otel code {otel_code}");
        }
    }

    #[test]
    fn end_time_zero_means_open_span() {
        let mut span = sample_span();
        span.end_time_unix_nano = 0;
        let body = wrap_in_request(span, vec![]);
        let spans = decode_otlp_protobuf(&body, Some(&tenant())).unwrap();
        assert!(spans[0].end_time.is_none());
    }

    #[test]
    fn rejects_malformed_trace_id_length() {
        let mut span = sample_span();
        span.trace_id = vec![1u8; 15]; // wrong length
        let body = wrap_in_request(span, vec![]);
        let result = decode_otlp_protobuf(&body, Some(&tenant()));
        assert!(result.is_err());
    }

    // ── ADR-032 semconv v1.34 → v1.41 store-side normalization ──────────────
    // PP-SCHEMA-EVOLUTION: a legacy adapter (`gen_ai.system`) and a v1.41
    // adapter (`gen_ai.provider.name`) must land in identical canonical rows.

    fn kv_str(key: &str, val: &str) -> ProtoKeyValue {
        ProtoKeyValue {
            key: key.into(),
            value: Some(ProtoAnyValue {
                value: Some(ProtoValue::StringValue(val.into())),
            }),
        }
    }

    fn kv_int(key: &str, val: i64) -> ProtoKeyValue {
        ProtoKeyValue {
            key: key.into(),
            value: Some(ProtoAnyValue {
                value: Some(ProtoValue::IntValue(val)),
            }),
        }
    }

    #[test]
    fn legacy_gen_ai_system_normalizes_to_canonical_provider_name() {
        // A pre-1.36 adapter emits only `gen_ai.system`.
        let legacy = build_attributes(&[
            kv_str("gen_ai.system", "openai"),
            kv_int("gen_ai.usage.input_tokens", 42),
        ]);
        // A v1.41 adapter emits `gen_ai.provider.name`.
        let modern = build_attributes(&[
            kv_str("gen_ai.provider.name", "openai"),
            kv_int("gen_ai.usage.input_tokens", 42),
        ]);
        // Both land on the canonical column with identical values.
        assert_eq!(legacy.gen_ai_provider_name.as_deref(), Some("openai"));
        assert_eq!(modern.gen_ai_provider_name.as_deref(), Some("openai"));
        assert_eq!(legacy.gen_ai_provider_name, modern.gen_ai_provider_name);
        assert_eq!(
            legacy.gen_ai_usage_input_tokens,
            modern.gen_ai_usage_input_tokens
        );
    }

    #[test]
    fn provider_name_wins_over_legacy_system_regardless_of_order() {
        // v1.41 key after legacy key.
        let a = build_attributes(&[
            kv_str("gen_ai.system", "legacy_value"),
            kv_str("gen_ai.provider.name", "canonical_value"),
        ]);
        // v1.41 key before legacy key.
        let b = build_attributes(&[
            kv_str("gen_ai.provider.name", "canonical_value"),
            kv_str("gen_ai.system", "legacy_value"),
        ]);
        assert_eq!(a.gen_ai_provider_name.as_deref(), Some("canonical_value"));
        assert_eq!(b.gen_ai_provider_name.as_deref(), Some("canonical_value"));
    }

    #[test]
    fn decodes_v1_41_cache_reasoning_stream_attributes() {
        let attrs = build_attributes(&[
            kv_str("gen_ai.provider.name", "anthropic"),
            kv_int("gen_ai.usage.cache_read.input_tokens", 100),
            kv_int("gen_ai.usage.cache_creation.input_tokens", 200),
            kv_int("gen_ai.usage.reasoning.output_tokens", 50),
            kv_str("gen_ai.conversation.id", "conv-123"),
            kv_str("gen_ai.agent.version", "v2.1.0"),
            ProtoKeyValue {
                key: "gen_ai.request.stream".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::BoolValue(true)),
                }),
            },
            ProtoKeyValue {
                key: "gen_ai.response.time_to_first_chunk".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::DoubleValue(0.234)),
                }),
            },
        ]);
        assert_eq!(attrs.gen_ai_usage_cache_read_input_tokens, Some(100));
        assert_eq!(attrs.gen_ai_usage_cache_creation_input_tokens, Some(200));
        assert_eq!(attrs.gen_ai_usage_reasoning_output_tokens, Some(50));
        assert_eq!(attrs.gen_ai_conversation_id.as_deref(), Some("conv-123"));
        assert_eq!(attrs.gen_ai_agent_version.as_deref(), Some("v2.1.0"));
        assert_eq!(attrs.gen_ai_request_stream, Some(true));
        assert_eq!(attrs.gen_ai_response_time_to_first_chunk, Some(0.234));
    }

    #[test]
    fn legacy_gen_ai_openai_prefix_normalizes_to_openai() {
        let attrs = build_attributes(&[kv_str(
            "gen_ai.openai.response.system_fingerprint",
            "fp_abc123",
        )]);
        assert_eq!(
            attrs
                .extra
                .get("openai.response.system_fingerprint")
                .and_then(|v| v.as_str()),
            Some("fp_abc123")
        );
        // The legacy-prefixed key is not retained.
        assert!(
            !attrs
                .extra
                .contains_key("gen_ai.openai.response.system_fingerprint")
        );
    }

    #[test]
    fn business_reference_is_promoted_and_length_bounded() {
        // In-bound value → promoted to the first-class field (not left in extra).
        let a = build_attributes(&[kv_str("tracelane.business_reference", "  LOAN-2026-42 ")]);
        assert_eq!(
            a.tracelane_business_reference.as_deref(),
            Some("LOAN-2026-42")
        );
        assert!(!a.extra.contains_key("tracelane.business_reference"));

        // Over-cap value → dropped (never truncated: a truncated id is a wrong id).
        let long = "x".repeat(crate::span::MAX_BUSINESS_REFERENCE_LEN + 1);
        let b = build_attributes(&[kv_str("tracelane.business_reference", &long)]);
        assert_eq!(b.tracelane_business_reference, None);
    }
}
