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

use tracelane_shared::{
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
        return Ok(TenantId::from_jwt_claim(uuid));
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
                    any_value_string(av).filter(|s| crate::federation::is_valid_aft_id(s));
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
                    .and_then(tracelane_shared::span::bounded_business_reference);
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
        let long = "x".repeat(tracelane_shared::span::MAX_BUSINESS_REFERENCE_LEN + 1);
        let b = build_attributes(&[kv_str("tracelane.business_reference", &long)]);
        assert_eq!(b.tracelane_business_reference, None);
    }
}
