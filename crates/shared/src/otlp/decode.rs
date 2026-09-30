//! OTLP protobuf decoder — converts incoming `ExportTraceServiceRequest`
//! payloads into Tracelane's internal `TracelaneSpan` shape.
//!
//! ## Scope
//!
//! Decodes the protobuf wire format (Content-Type
//! `application/x-protobuf`) and OTLP/JSON (`application/json`). Both formats
//! are decoded to the same protobuf model before validation and mapping.
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

use super::content::OtlpCapturePolicy;

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
    map_otlp_with_policy(req, peer_tenant, &OtlpCapturePolicy::embedded())
}

/// Map using the authenticated caller’s cached capture limits.
///
/// # Errors
/// Returns an error for an unresolvable tenant, malformed IDs or timestamps.
pub fn map_otlp_with_policy(
    req: ExportTraceServiceRequest,
    peer_tenant: Option<&TenantId>,
    policy: &OtlpCapturePolicy,
) -> Result<Vec<TracelaneSpan>> {
    map_otlp_with_policies(
        req,
        peer_tenant,
        policy,
        &crate::labels::LabelCaps::embedded(),
    )
}

/// Map using both cached reference policies; no per-span policy lookup.
pub fn map_otlp_with_policies(
    req: ExportTraceServiceRequest,
    peer_tenant: Option<&TenantId>,
    policy: &OtlpCapturePolicy,
    label_caps: &crate::labels::LabelCaps,
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
        let resource = resource_labels(resource_attrs);

        for scope_spans in resource_spans.scope_spans {
            for span in scope_spans.spans {
                let mapped = map_span(&tenant_id, span, policy, label_caps, &resource)?;

                out.push(mapped);
            }
        }
    }

    Ok(out)
}

#[derive(Default)]
struct ResourceLabels {
    service: Option<String>,
    version: Option<String>,
    environment: Option<String>,
    dropped: usize,
}

fn reported_service(av: &AnyValue) -> Option<String> {
    any_value_string(av)
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && s != "unknown-service" && !s.starts_with("unknown_service"))
}

fn resource_labels(attrs: &[KeyValue]) -> ResourceLabels {
    let mut labels = ResourceLabels::default();
    for kv in attrs {
        let Some(value) = &kv.value else {
            labels.dropped += 1;
            continue;
        };
        match kv.key.as_str() {
            "service.name" => labels.service = reported_service(value),
            "service.version" => labels.version = any_value_string(value),
            "deployment.environment.name" => labels.environment = any_value_string(value),
            "deployment.environment" => {
                if labels.environment.is_none() {
                    labels.environment = any_value_string(value);
                }
            }
            _ => labels.dropped += 1,
        }
    }
    labels
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

fn map_span(
    tenant_id: &TenantId,
    span: OtlpSpan,
    policy: &OtlpCapturePolicy,
    label_caps: &crate::labels::LabelCaps,
    resource: &ResourceLabels,
) -> Result<TracelaneSpan> {
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

    let mut attributes = build_attributes_with_policy(&span.attributes, policy);
    attributes.service_name = attributes
        .service_name
        .take()
        .or_else(|| resource.service.clone());
    attributes.service_version = attributes
        .service_version
        .take()
        .or_else(|| resource.version.clone());
    attributes.deployment_environment = attributes
        .deployment_environment
        .take()
        .or_else(|| resource.environment.clone());
    super::content::note_drop(&mut attributes, "resource", resource.dropped);
    super::labels::apply(&span.attributes, &mut attributes, label_caps);
    super::events::apply(&span, &mut attributes, policy);

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
pub fn otlp_trace_id_to_uuid(bytes: &[u8]) -> Result<Uuid> {
    if bytes.len() != 16 {
        bail!("OTLP trace_id must be 16 bytes, got {}", bytes.len());
    }
    let arr: [u8; 16] = bytes.try_into().expect("length checked above");
    Ok(Uuid::from_bytes(arr))
}

/// Convert an 8-byte OTLP span ID to a UUID by zero-padding the high
/// 8 bytes. The original 8-byte ID is recoverable as the low 64 bits.
///
/// `pub` since 2026-09-05 (ADR-075 / GWY-46): the gateway's inbound `traceparent` join
/// MUST use this exact transform for the parent id, or a framework span shipped via OTLP
/// would never match its gateway child. One transform, two callers, never a copy.
pub fn otlp_span_id_to_uuid(bytes: &[u8]) -> Result<Uuid> {
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

/// Decode curated metadata and stage bounded unknown attributes for the content gate.
#[cfg(test)]
fn build_attributes(attrs: &[KeyValue]) -> SpanAttributes {
    build_attributes_with_policy(attrs, &OtlpCapturePolicy::embedded())
}

fn build_attributes_with_policy(attrs: &[KeyValue], policy: &OtlpCapturePolicy) -> SpanAttributes {
    let mut out = SpanAttributes::default();
    for kv in attrs {
        let Some(av) = &kv.value else { continue };
        let key = kv.key.as_str();
        match key {
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
            // RI-05 (2026-09-19): the two response-identity keys the SDK path may carry.
            "gen_ai.response.id" => out.gen_ai_response_id = any_value_string(av),
            "gen_ai.response.finish_reason" if out.gen_ai_response_finish_reasons.is_none() => {
                out.gen_ai_response_finish_reasons = any_value_string(av).map(|value| vec![value]);
            }
            // Plural wins — but an EMPTY plural must not erase a singular value
            // already decoded (code review 2026-09-29).
            "gen_ai.response.finish_reasons" => {
                if let Some(v) = any_value_strings(av).filter(|v| !v.is_empty()) {
                    out.gen_ai_response_finish_reasons = Some(v);
                }
            }
            "gen_ai.operation.name" => out.gen_ai_operation_name = any_value_string(av),
            "gen_ai.agent.name" => out.gen_ai_agent_name = any_value_string(av),
            "gen_ai.agent.version" => out.gen_ai_agent_version = any_value_string(av),
            "gen_ai.conversation.id" => out.gen_ai_conversation_id = any_value_string(av),
            "tracelane.usage.input_includes_cache" => {
                out.tracelane_usage_input_includes_cache = any_value_bool(av);
            }
            "gen_ai.usage.cost" => {
                out.gen_ai_usage_cost = any_value_f64(av).filter(|v| v.is_finite() && *v >= 0.0);
            }
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
            // GWY-48 request configuration. These four have REGISTRY names, so an
            // SDK/OTLP span and a gateway-published span land in the SAME field —
            // the ADR-032 PP-SCHEMA-EVOLUTION property. Without these arms a
            // customer instrumenting with a stock OTel exporter would have their
            // temperature swept into `_extra` under a dotted key, and any query
            // over `gen_ai_request_temperature` would see gateway traffic only.
            //
            // The four `tracelane.request.*` attributes deliberately get NO arms:
            // they are OUR names, no SDK emits them, and adding arms for keys
            // nothing sends is a control that can never fire.
            // `any_value_f64(..) as f32`, NOT `any_value_f32`. `any_value_f32`
            // matches `DoubleValue` ONLY, so an SDK that encodes a whole-number
            // `temperature: 1` as an `IntValue` — legal, and what you get when the
            // value came from a JSON `1` rather than `1.0` — would decode to
            // `None`. That is the "absence is absence" rule producing a FALSE
            // absence, and no test that plants a double can see it.
            // `any_value_f64` accepts both encodings and exists for exactly this
            // reason (`ttft_ms` arrives as an int).
            "gen_ai.request.temperature" => {
                #[allow(clippy::cast_possible_truncation)]
                {
                    out.gen_ai_request_temperature = any_value_f64(av).map(|v| v as f32);
                }
            }
            "gen_ai.request.top_p" => {
                #[allow(clippy::cast_possible_truncation)]
                {
                    out.gen_ai_request_top_p = any_value_f64(av).map(|v| v as f32);
                }
            }
            "gen_ai.request.max_tokens" => {
                out.gen_ai_request_max_tokens = any_value_u32(av);
            }
            // `u64` and not `u32`: a seed is an opaque 64-bit number, and
            // silently dropping every seed above 4.29e9 would make the attribute
            // absent exactly where a caller was most deliberate about it.
            "gen_ai.request.seed" => {
                out.gen_ai_request_seed = any_value_u64(av);
            }
            // PLT-46: Claude Code's own OTLP exporter spells these facts differently
            // from the GenAI semconv. Every arm below only sets the field when it is
            // still `None`, so a canonical `gen_ai.*` key — whichever order it arrives
            // in relative to the alias — always wins (same idiom as `gen_ai.system` /
            // `gen_ai.provider.name` above and `tool.name` below). Tested both orders.
            // Guarded match arms, not a nested `if`: when the guard is false there is
            // no other arm for this literal, so the key falls through to `_` and is
            // dropped — same effect as the canonical key having already won.
            "session.id" if out.gen_ai_conversation_id.is_none() => {
                out.gen_ai_conversation_id = any_value_string(av);
            }
            // ── OBS-20: the customer's own end user ──────────────────────────
            // `user.id` is the canonical spelling and is a three-for-one: it is
            // the OTel registry attribute, OpenInference's reserved attribute,
            // and one of Langfuse's two accepted spellings. The others are
            // aliases onto the SAME field, guarded `is_none()` so the canonical
            // key wins whichever order it arrives in — the `session.id` idiom
            // directly above.
            //
            // Among the three ALIASES it is first-one-wins in attribute order,
            // not a preference ranking — they share one guarded arm. Said
            // explicitly because the obvious reading is that `enduser.pseudo.id`
            // (the non-PII spelling by definition) outranks `enduser.id`, and it
            // does not. Ranking them would need a second field tracking which
            // spelling won, to serve a producer that sends two contradictory
            // ids for the same user — which is a bug in that producer, not a
            // case worth carrying state for.
            //
            // There is deliberately no `user.email` / `user.name` arm. Those are
            // PII by name rather than by accident, and ingest's `redact_json`
            // would turn an email into `[REDACTED:email]` anyway — decoding it
            // would only manufacture a field that is always a placeholder.
            "user.id" => {
                out.user_id =
                    any_value_string(av).and_then(|s| crate::span::bounded_end_user_id(&s));
            }
            "enduser.pseudo.id" | "enduser.id" | "langfuse.user.id" if out.user_id.is_none() => {
                out.user_id =
                    any_value_string(av).and_then(|s| crate::span::bounded_end_user_id(&s));
            }
            "input_tokens" if out.gen_ai_usage_input_tokens.is_none() => {
                out.gen_ai_usage_input_tokens = any_value_u32(av);
            }
            "output_tokens" if out.gen_ai_usage_output_tokens.is_none() => {
                out.gen_ai_usage_output_tokens = any_value_u32(av);
            }
            "cache_read_tokens" if out.gen_ai_usage_cache_read_input_tokens.is_none() => {
                out.gen_ai_usage_cache_read_input_tokens = any_value_u32(av);
            }
            "cache_creation_tokens" if out.gen_ai_usage_cache_creation_input_tokens.is_none() => {
                out.gen_ai_usage_cache_creation_input_tokens = any_value_u32(av);
            }
            // Claude Code emits `ttft_ms` in milliseconds; the canonical column
            // (`gen_ai.response.time_to_first_chunk`, migration 04's
            // `time_to_first_chunk_s`) is SECONDS — confirmed at `trace_reads.rs`
            // (`JSONExtractFloat(...) * 1000` to render ms), so divide by 1000 here
            // rather than pushing the conversion onto every reader.
            "ttft_ms" if out.gen_ai_response_time_to_first_chunk.is_none() => {
                out.gen_ai_response_time_to_first_chunk = any_value_f64(av).map(|ms| ms / 1000.0);
            }
            // `model` only fills the request-model column when the canonical semconv
            // key never set it — Claude Code emits `model` on some span kinds where
            // `gen_ai.request.model` is absent entirely, not merely a duplicate of it.
            "model" if out.gen_ai_request_model.is_none() => {
                out.gen_ai_request_model = any_value_string(av);
            }
            "service.name" => out.service_name = reported_service(av),
            "service.version" => out.service_version = any_value_string(av),
            "deployment.environment.name" => out.deployment_environment = any_value_string(av),
            "deployment.environment" if out.deployment_environment.is_none() => {
                out.deployment_environment = any_value_string(av)
            }
            "gen_ai.usage.cache_write.input_tokens"
                if out.gen_ai_usage_cache_creation_input_tokens.is_none() =>
            {
                out.gen_ai_usage_cache_creation_input_tokens = any_value_u32(av)
            }
            "gen_ai.tool.call.id" => out.gen_ai_tool_call_id = any_value_string(av),
            "gen_ai.tool.call.arguments" => out.gen_ai_tool_call_arguments = content_text(av),
            "gen_ai.tool.call.result" => out.gen_ai_tool_call_result = content_text(av),
            "gen_ai.retrieval.query.text" => out.tracelane_retrieval_query = any_value_string(av),
            "error.type" => out.error_type = any_value_string(av),
            "gen_ai.retrieval.documents" => {
                if let Some(serde_json::Value::Array(values)) = any_value_json(av) {
                    super::content::note_drop(
                        &mut out,
                        "cap",
                        values.len().saturating_sub(policy.max_retrieval_documents),
                    );
                    out.tracelane_retrieval_documents = Some(
                        values
                            .into_iter()
                            .take(policy.max_retrieval_documents)
                            .map(|v| crate::span::RetrievalDocument {
                                id: v
                                    .get("id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned),
                                score: v
                                    .get("score")
                                    .and_then(serde_json::Value::as_f64)
                                    .filter(|v| v.is_finite()),
                                content: v
                                    .get("content")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned),
                            })
                            .collect(),
                    );
                }
            }
            "gen_ai.tool.definitions" => {
                if let Some(serde_json::Value::Array(values)) = any_value_json(av) {
                    super::openinference::record_tools(&mut out, values.into_iter(), policy);
                }
            }
            "mcp.tool_name" => {
                if let Some(v) = any_value_string(av) {
                    out.extra
                        .entry("gen_ai.tool.name".into())
                        .or_insert(serde_json::Value::String(v));
                }
            }
            "gen_ai.tool.type"
            | "gen_ai.tool.description"
            | "gen_ai.data_source.id"
            | "gen_ai.prompt.name"
            | "gen_ai.prompt.version"
            | "gen_ai.agent.description"
            | "gen_ai.workflow.name"
            | "gen_ai.output.type"
            | "mcp.method.name"
            | "mcp.session.id"
            | "mcp.protocol.version"
            | "mcp.resource.uri" => {
                super::openinference::metadata(
                    &mut out,
                    key,
                    any_value_string(av).map(serde_json::Value::String),
                    policy,
                );
            }
            "gen_ai.conversation.compacted" | "mcp.is_error" => {
                super::openinference::metadata(
                    &mut out,
                    key,
                    any_value_bool(av).map(serde_json::Value::Bool),
                    policy,
                );
            }
            "gen_ai.retrieval.top_k"
            | "gen_ai.request.top_k"
            | "gen_ai.request.frequency_penalty"
            | "gen_ai.request.presence_penalty"
            | "gen_ai.request.choice.count"
            | "mcp.content_count"
            | "mcp.argument_count" => {
                super::openinference::metadata(
                    &mut out,
                    key,
                    super::openinference::scalar(av).filter(serde_json::Value::is_number),
                    policy,
                );
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
            // B-232 (2026-09-05): `GET /v1/query/tool-analytics` reads
            // `JSONExtractString(attributes, 'gen_ai.tool.name')` and NO ingest path
            // ever wrote that key — the decoder dropped it here, so the page rendered
            // empty for every tenant, always. `extra` is `#[serde(flatten)]`, so a
            // dotted key placed there lands in the `attributes` JSON exactly as the
            // SQL reads it. OpenInference (item 14's LangChain/LangGraph path) spells
            // the same fact `tool.name`; it maps to the canonical key so those tool
            // spans count too, and the canonical spelling wins when both are present.
            "gen_ai.tool.name" => {
                if let Some(v) = any_value_string(av) {
                    out.extra
                        .insert("gen_ai.tool.name".to_string(), serde_json::Value::String(v));
                }
            }
            "tool.name" => {
                if let Some(v) = any_value_string(av) {
                    out.extra
                        .entry("gen_ai.tool.name".to_string())
                        .or_insert(serde_json::Value::String(v));
                }
            }
            // PLT-46: Claude Code's own spelling for the same fact. Same
            // `or_insert` idiom as `tool.name` above, so the canonical
            // `gen_ai.tool.name` wins regardless of attribute order.
            "tool_name" => {
                if let Some(v) = any_value_string(av) {
                    out.extra
                        .entry("gen_ai.tool.name".to_string())
                        .or_insert(serde_json::Value::String(v));
                }
            }
            // OBS-49: OTel GenAI semconv / OpenInference agent identity, needed
            // to build multi-agent swimlanes client-side. `extra` is
            // `#[serde(flatten)]`, so this lands in the `attributes` JSON under
            // the dotted key exactly as `lib/trace/lanes.ts` reads it — same
            // pattern as `gen_ai.tool.name` above.
            "gen_ai.agent.id" => {
                if let Some(v) = any_value_string(av) {
                    out.extra
                        .insert("gen_ai.agent.id".to_string(), serde_json::Value::String(v));
                }
            }
            // Claude Code's own spelling for the same fact (PLT-46 spec). Same
            // `or_insert` idiom as `tool.name`/`tool_name`, so the canonical
            // `gen_ai.agent.id` wins regardless of attribute order.
            "agent_id" => {
                if let Some(v) = any_value_string(av) {
                    out.extra
                        .entry("gen_ai.agent.id".to_string())
                        .or_insert(serde_json::Value::String(v));
                }
            }
            // Claude Code's sub-agent hand-off parent — no competing spelling
            // exists today, so this is a plain insert rather than an
            // `.or_insert` alias.
            "parent_agent_id" => {
                if let Some(v) = any_value_string(av) {
                    out.extra.insert(
                        "gen_ai.agent.parent_id".to_string(),
                        serde_json::Value::String(v),
                    );
                }
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
            // RI-05 (2026-09-19): M18 — the caller's own step counter inside a
            // multi-step agent loop. No registry name exists, hence
            // `tracelane.*`. Before this arm existed the key fell into the `_`
            // catch-all below and was silently dropped — RED proven by hand
            // (this arm and the one below commented out, the test's first two
            // assertions failed: `None` where `Some(3)`/`Some(true)` were
            // expected), then restored GREEN.
            "tracelane.agent.step_index" => {
                out.tracelane_agent_step_index = any_value_u32(av);
            }
            // RI-05: M20 — the client's own context-trim signal. Always absent
            // on a gateway-proxied span (the proxy cannot know it); this arm
            // is what lets an SDK that DOES know set it.
            "tracelane.context.truncated" => {
                out.tracelane_context_truncated = any_value_bool(av);
            }
            "tracelane.business_reference" => {
                // Customer-supplied free text — length-bound at the ingest
                // boundary (same posture as the aft_id taxonomy guard above) so
                // an oversized value never enters a span or the export.
                out.tracelane_business_reference = any_value_string(av)
                    .as_deref()
                    .and_then(crate::span::bounded_business_reference);
            }
            "gen_ai.openai.response.system_fingerprint" | "openai.response.system_fingerprint" => {
                super::openinference::metadata(
                    &mut out,
                    "openai.response.system_fingerprint",
                    any_value_string(av).map(serde_json::Value::String),
                    policy,
                );
            }
            k if k.starts_with("gen_ai.openai.") => {
                let renamed = k.replacen("gen_ai.openai.", "openai.", 1);
                super::passthrough::collect(&mut out, &renamed, av, policy, None);
            }
            // Aliases already resolved above must not re-enter the unknown-key path.
            "session.id"
            | "enduser.pseudo.id"
            | "enduser.id"
            | "langfuse.user.id"
            | "gen_ai.response.finish_reason"
            | "deployment.environment"
            | "gen_ai.usage.cache_write.input_tokens" => {}
            k if super::openinference::handles(k) || super::labels::handles(k) => {}
            _ => super::passthrough::collect(&mut out, key, av, policy, None),
        }
    }
    super::openinference::apply(attrs, &mut out, policy);
    out
}

pub(super) fn any_value_string(av: &AnyValue) -> Option<String> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s)) => {
            Some(s.clone())
        }
        _ => None,
    }
}

/// An OTLP array of strings (`gen_ai.response.finish_reasons`). Non-string elements
/// are skipped; an empty or non-array value is `None`, never `Some(vec![])`.
pub(super) fn any_value_strings(av: &AnyValue) -> Option<Vec<String>> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::ArrayValue(arr)) => {
            let v: Vec<String> = arr.values.iter().filter_map(any_value_string).collect();
            (!v.is_empty()).then_some(v)
        }
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s)) => {
            Some(vec![s.clone()])
        }
        _ => None,
    }
}

pub(super) fn any_value_u32(av: &AnyValue) -> Option<u32> {
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

pub(super) fn any_value_f32(av: &AnyValue) -> Option<f32> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::DoubleValue(d)) => {
            Some(*d as f32)
        }
        _ => None,
    }
}

/// GWY-48. A seed arrives as a protobuf `IntValue`, which is SIGNED. A negative
/// value is not a seed, so it is dropped rather than wrapped into a huge
/// positive one — a silently-wrong seed is worse than an absent one.
///
/// **A REAL CEILING, not a code smell:** OTLP's `AnyValue::IntValue` is an `i64`,
/// so a seed above `i64::MAX` — which the OpenAI API permits — is unrepresentable
/// on the OTLP wire whatever this function does. The GATEWAY path carries the
/// full `u64` (it reads `req.seed` directly); only the SDK/OTLP path is bounded.
pub(super) fn any_value_u64(av: &AnyValue) -> Option<u64> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue(n)) => {
            u64::try_from(*n).ok()
        }
        _ => None,
    }
}

pub(super) fn any_value_bool(av: &AnyValue) -> Option<bool> {
    match &av.value {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::BoolValue(b)) => Some(*b),
        _ => None,
    }
}

pub(super) fn any_value_f64(av: &AnyValue) -> Option<f64> {
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
pub(super) fn any_value_json(av: &AnyValue) -> Option<serde_json::Value> {
    if let Some(s) = any_value_string(av) {
        return Some(serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s)));
    }
    wire_json(av)
}

fn content_text(av: &AnyValue) -> Option<String> {
    any_value_string(av).or_else(|| wire_json(av).map(|v| v.to_string()))
}

pub(super) fn wire_json(av: &AnyValue) -> Option<serde_json::Value> {
    use opentelemetry_proto::tonic::common::v1::any_value::Value as Wire;
    match av.value.as_ref()? {
        Wire::ArrayValue(a) => Some(serde_json::Value::Array(
            a.values.iter().filter_map(wire_json).collect(),
        )),
        Wire::KvlistValue(kv) => Some(serde_json::Value::Object(
            kv.values
                .iter()
                .filter_map(|kv| Some((kv.key.clone(), wire_json(kv.value.as_ref()?)?)))
                .collect(),
        )),
        _ => super::openinference::scalar(av),
    }
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
    decode_batch_with_policy(
        body,
        tenant,
        cap,
        max_spans,
        wire,
        &OtlpCapturePolicy::embedded(),
    )
}

/// Decode either wire format using cached limits for optional retained fields.
pub fn decode_batch_with_policy(
    body: &[u8],
    tenant: &TenantId,
    cap: &crate::otlp::limits::IngestLimits,
    max_spans: usize,
    wire: Wire,
    policy: &OtlpCapturePolicy,
) -> DecodeOutcome {
    decode_batch_with_policies(
        body,
        tenant,
        cap,
        max_spans,
        wire,
        policy,
        &crate::labels::LabelCaps::embedded(),
    )
}

/// Decode with the gateway's cached content and label limits.
pub fn decode_batch_with_policies(
    body: &[u8],
    tenant: &TenantId,
    cap: &crate::otlp::limits::IngestLimits,
    max_spans: usize,
    wire: Wire,
    policy: &OtlpCapturePolicy,
    label_caps: &crate::labels::LabelCaps,
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

    match map_otlp_with_policies(req, Some(tenant), policy, label_caps) {
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

    #[test]
    fn input_cache_convention_flag_survives_decode() {
        for flag in [true, false] {
            let attrs = build_attributes(&[ProtoKeyValue {
                key: "tracelane.usage.input_includes_cache".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::BoolValue(flag)),
                }),
            }]);
            assert_eq!(
                serde_json::to_value(attrs).unwrap()["tracelane_usage_input_includes_cache"],
                flag
            );
        }
    }

    #[test]
    fn singular_finish_reason_is_preserved_and_plural_wins_both_orders() {
        let singular = kv_str("gen_ai.response.finish_reason", "stop");
        assert_eq!(
            build_attributes(std::slice::from_ref(&singular)).gen_ai_response_finish_reasons,
            Some(vec!["stop".into()])
        );
        let plural = ProtoKeyValue {
            key: "gen_ai.response.finish_reasons".into(),
            value: Some(ProtoAnyValue {
                value: Some(ProtoValue::ArrayValue(
                    opentelemetry_proto::tonic::common::v1::ArrayValue {
                        values: vec![ProtoAnyValue {
                            value: Some(ProtoValue::StringValue("length".into())),
                        }],
                    },
                )),
            }),
        };
        for attrs in [
            vec![singular.clone(), plural.clone()],
            vec![plural, singular],
        ] {
            assert_eq!(
                build_attributes(&attrs).gen_ai_response_finish_reasons,
                Some(vec!["length".into()])
            );
        }
        assert!(
            build_attributes(&[kv_int("gen_ai.response.finish_reason", 1)])
                .gen_ai_response_finish_reasons
                .is_none()
        );
    }

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap())
    }

    /// GWY-48. An SDK/OTLP span carrying the four REGISTRY-named request-config
    /// attributes must land in the same `SpanAttributes` fields a gateway span
    /// does — the ADR-032 PP-SCHEMA-EVOLUTION property. Without the arms, these
    /// are swept into `extra` under dotted keys and any query over
    /// `gen_ai_request_temperature` silently sees gateway traffic only.
    #[test]
    fn otlp_request_config_attributes_land_in_the_same_fields_as_a_gateway_span() {
        let attrs = build_attributes(&[
            ProtoKeyValue {
                key: "gen_ai.request.temperature".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::DoubleValue(0.7)),
                }),
            },
            ProtoKeyValue {
                key: "gen_ai.request.top_p".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::DoubleValue(0.9)),
                }),
            },
            ProtoKeyValue {
                key: "gen_ai.request.max_tokens".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::IntValue(512)),
                }),
            },
            ProtoKeyValue {
                key: "gen_ai.request.seed".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::IntValue(9_007_199_254_740_993)),
                }),
            },
        ]);
        assert!((attrs.gen_ai_request_temperature.expect("temp") - 0.7).abs() < 1e-6);
        assert!((attrs.gen_ai_request_top_p.expect("top_p") - 0.9).abs() < 1e-6);
        assert_eq!(attrs.gen_ai_request_max_tokens, Some(512));
        assert_eq!(
            attrs.gen_ai_request_seed,
            Some(9_007_199_254_740_993),
            "a seed is 64-bit; narrowing it to u32 would drop exactly the values a \
             caller was most deliberate about"
        );
        assert!(
            !attrs.extra.contains_key("gen_ai.request.temperature"),
            "a mapped key must not ALSO sit in the catch-all"
        );
    }

    /// **A WHOLE-NUMBER TEMPERATURE ARRIVES AS AN `IntValue`, AND MUST NOT BE
    /// DROPPED.** `any_value_f32` matches `DoubleValue` only, so the obvious arm
    /// silently decodes `temperature: 1` to `None` — a FALSE absence, invisible
    /// to any test that plants a double. This is the falsification for that.
    #[test]
    fn an_integer_encoded_temperature_is_decoded_not_dropped() {
        let attrs = build_attributes(&[
            ProtoKeyValue {
                key: "gen_ai.request.temperature".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::IntValue(1)),
                }),
            },
            ProtoKeyValue {
                key: "gen_ai.request.top_p".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::IntValue(1)),
                }),
            },
        ]);
        assert_eq!(
            attrs.gen_ai_request_temperature,
            Some(1.0),
            "an int-encoded temperature must decode, not read as 'the client sent none'"
        );
        assert_eq!(attrs.gen_ai_request_top_p, Some(1.0));
    }

    /// A negative `IntValue` is not a seed. Dropped rather than wrapped into a
    /// huge positive one — a silently-wrong seed is worse than an absent one.
    #[test]
    fn a_negative_otlp_seed_is_dropped_not_wrapped() {
        let attrs = build_attributes(&[ProtoKeyValue {
            key: "gen_ai.request.seed".into(),
            value: Some(ProtoAnyValue {
                value: Some(ProtoValue::IntValue(-1)),
            }),
        }]);
        assert_eq!(attrs.gen_ai_request_seed, None);
    }

    /// RI-05 / B-444: the two response-identity keys the SDK path may carry, and the
    /// array form `finish_reasons` takes on the wire. A string value is accepted as a
    /// one-element list; an empty array is `None`, never `Some(vec![])`.
    #[test]
    fn response_id_and_finish_reasons_decode_and_empty_is_absent() {
        let attrs = build_attributes(&[
            ProtoKeyValue {
                key: "gen_ai.response.id".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::StringValue("chatcmpl-77".into())),
                }),
            },
            ProtoKeyValue {
                key: "gen_ai.response.finish_reasons".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::ArrayValue(
                        opentelemetry_proto::tonic::common::v1::ArrayValue {
                            values: vec![
                                ProtoAnyValue {
                                    value: Some(ProtoValue::StringValue("stop".into())),
                                },
                                ProtoAnyValue {
                                    value: Some(ProtoValue::IntValue(7)),
                                },
                            ],
                        },
                    )),
                }),
            },
        ]);
        assert_eq!(attrs.gen_ai_response_id.as_deref(), Some("chatcmpl-77"));
        assert_eq!(
            attrs.gen_ai_response_finish_reasons,
            Some(vec!["stop".to_string()]),
            "non-string elements are skipped"
        );
        let empty = build_attributes(&[ProtoKeyValue {
            key: "gen_ai.response.finish_reasons".into(),
            value: Some(ProtoAnyValue {
                value: Some(ProtoValue::ArrayValue(
                    opentelemetry_proto::tonic::common::v1::ArrayValue { values: vec![] },
                )),
            }),
        }]);
        assert_eq!(
            empty.gen_ai_response_finish_reasons, None,
            "empty is absent"
        );
        let single = build_attributes(&[ProtoKeyValue {
            key: "gen_ai.response.finish_reasons".into(),
            value: Some(ProtoAnyValue {
                value: Some(ProtoValue::StringValue("length".into())),
            }),
        }]);
        assert_eq!(
            single.gen_ai_response_finish_reasons,
            Some(vec!["length".to_string()])
        );
    }

    /// RI-05 (2026-09-19): M18 + M20 — `tracelane.agent.step_index` and
    /// `tracelane.context.truncated` decode and round-trip.
    ///
    /// Before the two arms existed, both keys fell into the `_` catch-all
    /// (`_ => { /* Unmapped attribute — ignored for V1. */ }`) and were
    /// silently dropped — proven by the RED half below, which reads the two
    /// fields with the arms' PRODUCTION NAMES removed from the match (simulated
    /// by decoding an attribute this match genuinely does not have an arm for,
    /// `tracelane.agent.step_index.NOT_A_REAL_KEY`, the same catch-all path the
    /// real keys took before this commit added their arms).
    #[test]
    fn agent_step_index_and_context_truncated_decode_and_the_pre_arm_drop_is_demonstrated() {
        let attrs = build_attributes(&[
            ProtoKeyValue {
                key: "tracelane.agent.step_index".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::IntValue(3)),
                }),
            },
            ProtoKeyValue {
                key: "tracelane.context.truncated".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::BoolValue(true)),
                }),
            },
        ]);
        assert_eq!(attrs.tracelane_agent_step_index, Some(3));
        assert_eq!(attrs.tracelane_context_truncated, Some(true));

        // RED, demonstrated directly: a key this match has no arm for takes the
        // SAME `_` catch-all the two keys above took before their arms existed
        // — dropped without a trace, not an error, which is exactly why B-444's
        // sibling defect (M8) went unnoticed for so long (CLAUDE.md §1: a
        // silent drop proves nothing was watching, so prove the drop itself).
        let dropped = build_attributes(&[ProtoKeyValue {
            key: "tracelane.agent.step_index.not_a_real_key".into(),
            value: Some(ProtoAnyValue {
                value: Some(ProtoValue::IntValue(99)),
            }),
        }]);
        assert_eq!(
            dropped.tracelane_agent_step_index, None,
            "an unmapped key must be dropped, not misfiled onto a real field"
        );
        assert!(
            dropped.extra.is_empty(),
            "the catch-all does not even stash it in `extra` — it is gone"
        );

        // Absent-means-absent: a span carrying neither key sets neither field.
        let neither = build_attributes(&[]);
        assert_eq!(neither.tracelane_agent_step_index, None);
        assert_eq!(neither.tracelane_context_truncated, None);
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
    fn label_otlp_uses_runtime_caps_on_span_and_resource_values() {
        let mut wire = sample_span();
        wire.attributes = vec![
            kv_str("tracelane.metadata.first", "kept"),
            kv_str("tracelane.metadata.second", "dropped"),
            ProtoKeyValue {
                key: "tracelane.tags".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::ArrayValue(
                        opentelemetry_proto::tonic::common::v1::ArrayValue {
                            values: vec![
                                kv_str("", "beta").value.unwrap(),
                                kv_str("", "gamma").value.unwrap(),
                                kv_int("", 3).value.unwrap(),
                            ],
                        },
                    )),
                }),
            },
        ];
        let request = ExportTraceServiceRequest::decode(
            wrap_in_request(
                wire,
                vec![kv_str("deployment.environment.name", "production")],
            )
            .as_slice(),
        )
        .unwrap();
        let mut caps = crate::labels::LabelCaps::embedded();
        caps.max_metadata_keys = 1;
        caps.max_tags = 1;
        caps.max_environment_bytes = 3;
        let span = map_otlp_with_policies(
            request,
            Some(&tenant()),
            &OtlpCapturePolicy::embedded(),
            &caps,
        )
        .unwrap()
        .remove(0);
        let a = serde_json::to_value(span.attributes).unwrap();
        assert_eq!(a["tracelane_metadata"], serde_json::json!({"first":"kept"}));
        assert_eq!(a["tracelane_tags"], serde_json::json!(["beta"]));
        assert!(a.get("deployment_environment").is_none());
        assert_eq!(
            a["tracelane_labels_dropped"],
            serde_json::json!({"metadata_keys":1,"tags":2,"environment":1})
        );
    }

    #[test]
    fn label_otlp_aliases_share_bounds_and_canonical_precedence() {
        use super::super::content::{CaptureHalves, apply_capture};
        let mut attrs = vec![
            kv_str(
                "metadata",
                r#"{"feature":"openinference","n":2,"nested":{}}"#,
            ),
            kv_str("langfuse.trace.metadata.feature", "langfuse"),
            kv_str("tracelane.metadata.feature", "canonical"),
            kv_str("tag.tags", "openinference"),
            kv_str("langfuse.trace.tags", "langfuse"),
            kv_str("tracelane.tags", "canonical"),
            kv_str("service.version", &"x".repeat(129)),
        ];
        for _ in 0..2 {
            let mut wire = sample_span();
            wire.attributes = attrs.clone();
            let mut span = decode_otlp_protobuf(
                &wrap_in_request(
                    wire,
                    vec![
                        kv_str("service.name", "checkout"),
                        kv_str("deployment.environment.name", " Production "),
                    ],
                ),
                Some(&tenant()),
            )
            .unwrap()
            .remove(0);
            apply_capture(&mut span, &CaptureHalves::closed());
            let a = serde_json::to_value(span.attributes).unwrap();
            assert_eq!(
                a["tracelane_metadata"],
                serde_json::json!({"feature":"canonical","n":"2"})
            );
            assert_eq!(a["tracelane_tags"], serde_json::json!(["canonical"]));
            assert_eq!(a["deployment_environment"], "production");
            assert_eq!(a["service_name"], "checkout");
            assert!(a.get("service_version").is_none());
            assert_eq!(a["tracelane_labels_dropped"]["metadata_keys"], 1);
            assert_eq!(a["tracelane_labels_dropped"]["release"], 1);
            assert!(a.get("langfuse.trace.metadata.feature").is_none());
            attrs.reverse();
        }
        for attributes in [
            vec![
                kv_str("metadata", r#"{"feature":"checkout"}"#),
                kv_str("tag.tags", "beta"),
            ],
            vec![
                kv_str("langfuse.trace.metadata.feature", "checkout"),
                kv_str("langfuse.trace.tags", "beta"),
            ],
        ] {
            let mut wire = sample_span();
            wire.attributes = attributes;
            let span = decode_otlp_protobuf(&wrap_in_request(wire, vec![]), Some(&tenant()))
                .unwrap()
                .remove(0);
            let a = serde_json::to_value(span.attributes).unwrap();
            assert_eq!(a["tracelane_metadata"]["feature"], "checkout");
            assert_eq!(a["tracelane_tags"], serde_json::json!(["beta"]));
        }
    }

    #[test]
    fn passthrough_arrays_and_events_share_the_runtime_budget() {
        use super::super::content::{CaptureHalves, apply_capture};
        let mut caps = OtlpCapturePolicy::embedded();
        caps.passthrough_max_keys_per_span = 2;
        caps.passthrough_max_array_items = 2;
        let mut wire = sample_span();
        wire.attributes = vec![
            ProtoKeyValue {
                key: "custom.array".into(),
                value: Some(ProtoAnyValue {
                    value: Some(ProtoValue::ArrayValue(
                        opentelemetry_proto::tonic::common::v1::ArrayValue {
                            values: vec![
                                kv_str("", "secret").value.unwrap(),
                                kv_int("", 7).value.unwrap(),
                                kv_int("", 8).value.unwrap(),
                            ],
                        },
                    )),
                }),
            },
            kv_int("custom.number", 9),
        ];
        wire.events = vec![opentelemetry_proto::tonic::trace::v1::span::Event {
            name: "custom".into(),
            attributes: vec![kv_int("custom.event", 10)],
            ..Default::default()
        }];
        let request =
            ExportTraceServiceRequest::decode(wrap_in_request(wire, vec![]).as_slice()).unwrap();
        let mut span = map_otlp_with_policy(request, Some(&tenant()), &caps)
            .unwrap()
            .remove(0);
        apply_capture(&mut span, &CaptureHalves::closed());
        let a = serde_json::to_value(span.attributes).unwrap();
        assert_eq!(a["custom.array"], serde_json::json!([7]));
        assert_eq!(a["custom.number"], 9);
        assert!(
            a["tracelane_events"][0]["attributes"]
                .get("custom.event")
                .is_none()
        );
        assert_eq!(a["tracelane_attrs_dropped"]["reasons"]["cap"], 2);
        assert_eq!(
            a["tracelane_attrs_dropped"]["reasons"]["string_capture_off"],
            1
        );
    }

    #[test]
    fn passthrough_enforces_key_content_string_and_count_budgets() {
        use super::super::content::{CaptureHalves, apply_capture};
        let mut attrs = vec![
            kv_str("tracelane_api_key_id", "forged"),
            kv_int("gen_ai_usage_cost", 99),
            kv_int("tracelane.failover.activated", 1),
            kv_str("gen_ai.prompt.0.content", "secret"),
            kv_str("custom.label", "secret"),
            kv_str("custom.large", &"x".repeat(257)),
            kv_str("openai.private", "secret"),
        ];
        for i in 0..40 {
            attrs.push(kv_int(&format!("custom.n{i}"), i));
        }
        for (input, output) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut wire = sample_span();
            wire.attributes = attrs.clone();
            let mut span = decode_otlp_protobuf(&wrap_in_request(wire, vec![]), Some(&tenant()))
                .unwrap()
                .remove(0);
            // Candidates cannot leak if accidentally serialized before the decision.
            assert!(!serde_json::to_string(&span).unwrap().contains("secret"));
            apply_capture(
                &mut span,
                &CaptureHalves {
                    input,
                    output,
                    max_field_bytes: 65536,
                },
            );
            let a = serde_json::to_value(&span.attributes).unwrap();
            for key in [
                "tracelane_api_key_id",
                "gen_ai_usage_cost",
                "tracelane.failover.activated",
                "gen_ai.prompt.0.content",
                "custom.large",
            ] {
                assert!(a.get(key).is_none(), "{key}");
            }
            assert_eq!(span.attributes.extra.len(), 32);
            assert_eq!(a["custom.n0"], 0);
            assert_eq!(a.get("custom.label").is_some(), input && output);
            assert_eq!(
                a["tracelane_attrs_dropped"]["reasons"]["content_unmapped"],
                1
            );
            assert!(a["tracelane_attrs_dropped"]["count"].as_u64().unwrap() >= 13);
        }
    }

    #[test]
    fn resource_metadata_reaches_every_span_with_span_and_current_key_precedence() {
        let mut resource = vec![
            kv_str("service.name", "checkout"),
            kv_str("service.version", "v1"),
            kv_str("deployment.environment.name", "Production"),
            kv_str("deployment.environment", "legacy"),
            kv_str("telemetry.sdk.language", "python"),
        ];
        for _ in 0..2 {
            let bytes = wrap_in_request(sample_span(), resource.clone());
            let mut req = ExportTraceServiceRequest::decode(bytes.as_slice()).unwrap();
            let mut custom = sample_span();
            custom.attributes.extend([
                kv_str("service.name", "worker"),
                kv_str("service.version", "v2"),
                kv_str("deployment.environment", "staging"),
            ]);
            req.resource_spans[0].scope_spans[0].spans.push(custom);
            let spans = map_otlp_to_tracelane_spans(req, Some(&tenant())).unwrap();
            assert_eq!(spans.len(), 2);
            for (i, span) in spans.into_iter().enumerate() {
                assert_eq!(span.tenant_id, tenant());
                let a = serde_json::to_value(span.attributes).unwrap();
                assert_eq!(
                    a["service_name"],
                    if i == 0 { "checkout" } else { "worker" }
                );
                assert_eq!(a["service_version"], if i == 0 { "v1" } else { "v2" });
                assert_eq!(
                    a["deployment_environment"],
                    if i == 0 { "production" } else { "staging" }
                );
                assert_eq!(a["tracelane_attrs_dropped"]["reasons"]["resource"], 1);
                assert!(a.get("telemetry.sdk.language").is_none());
            }
            resource.reverse();
        }
        for name in [
            "unknown-service",
            "unknown_service",
            "unknown_service:python",
        ] {
            let bytes = wrap_in_request(sample_span(), vec![kv_str("service.name", name)]);
            let spans = decode_otlp_protobuf(&bytes, Some(&tenant())).unwrap();
            assert!(
                serde_json::to_value(&spans[0].attributes)
                    .unwrap()
                    .get("service_name")
                    .is_none()
            );
        }
    }

    #[test]
    fn events_fold_content_preserve_exception_metadata_and_convert_links() {
        use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
        let mut proto = sample_span();
        proto.events = vec![
            Event {
                name: "exception".into(),
                time_unix_nano: 123000,
                attributes: vec![
                    kv_str("exception.type", "ValueError"),
                    kv_str("exception.message", "bad value"),
                    kv_str("exception.stacktrace", &"é".repeat(100)),
                ],
                ..Default::default()
            },
            Event {
                name: "gen_ai.choice".into(),
                attributes: vec![kv_str(
                    "message",
                    r#"{"role":"assistant","content":"private choice"}"#,
                )],
                ..Default::default()
            },
            Event {
                name: "gen_ai.user.message".into(),
                attributes: vec![kv_str("content", "private input")],
                ..Default::default()
            },
            Event {
                name: "gen_ai.evaluation.result".into(),
                attributes: vec![
                    kv_str("gen_ai.evaluation.name", "quality"),
                    kv_double("score.value", 0.8),
                    kv_str("explanation", "private explanation"),
                ],
                ..Default::default()
            },
            Event {
                name: "custom".into(),
                attributes: vec![
                    kv_str("custom.secret", "private extra"),
                    kv_int("custom.count", 4),
                    kv_str("custom.content", "private unmapped"),
                ],
                ..Default::default()
            },
        ];
        proto.links = vec![Link {
            trace_id: vec![1; 16],
            span_id: vec![3; 8],
            attributes: vec![kv_str("link.secret", "private link")],
            ..Default::default()
        }];
        let bytes = wrap_in_request(proto, vec![]);
        let request = ExportTraceServiceRequest::decode(bytes.as_slice()).unwrap();
        let mut policy = OtlpCapturePolicy::embedded();
        policy.max_stacktrace_bytes = 40;
        let mut spans = map_otlp_with_policy(request, Some(&tenant()), &policy).unwrap();
        let span = &mut spans[0];
        let a = serde_json::to_value(&span.attributes).unwrap();
        assert_eq!(a["exception_type"], "ValueError");
        assert_eq!(a["exception_message"], "bad value");
        assert_eq!(a["gen_ai_output_messages"][0]["content"], "private choice");
        assert_eq!(a["tracelane_events"][0]["time_unix_us"], 123);
        let stack = a["tracelane_events"][0]["attributes"]["exception.stacktrace"]
            .as_str()
            .unwrap();
        assert!(stack.len() <= 40);
        assert!(stack.ends_with("…[truncated]"));
        assert_eq!(
            a["tracelane_links"][0]["span_id"],
            span.parent_span_id.unwrap().to_string()
        );
        assert_eq!(
            a["tracelane_links"][0]["trace_id"],
            span.trace_id.to_string()
        );
        super::super::content::apply_capture(span, &super::super::content::CaptureHalves::closed());
        let a = serde_json::to_value(&span.attributes).unwrap();
        assert!(!a.to_string().contains("private"));
        assert_eq!(a["tracelane_events"][2]["attributes"]["custom.count"], 4);
        assert_eq!(a["tracelane_attrs_dropped"]["reasons"]["link_attrs"], 1);
        assert_eq!(
            a["tracelane_attrs_dropped"]["reasons"]["string_capture_off"],
            1
        );
        assert_eq!(
            a["tracelane_attrs_dropped"]["reasons"]["content_unmapped"],
            1
        );
        assert_eq!(
            a["tracelane_content_withheld"],
            serde_json::json!(["input", "output"])
        );
    }

    #[test]
    fn event_and_link_budgets_count_drops_and_canonical_content_wins() {
        use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
        let mut proto = sample_span();
        proto.attributes.push(kv_str(
            "gen_ai.output.messages",
            r#"[{"content":"canonical"}]"#,
        ));
        proto.events = vec![
            Event {
                name: "gen_ai.choice".into(),
                attributes: vec![kv_str("message", r#"{"content":"alias"}"#)],
                ..Default::default()
            },
            Event {
                name: "later".into(),
                ..Default::default()
            },
        ];
        proto.links = vec![
            Link {
                trace_id: vec![1; 16],
                span_id: vec![3; 8],
                ..Default::default()
            };
            2
        ];
        let request =
            ExportTraceServiceRequest::decode(wrap_in_request(proto, vec![]).as_slice()).unwrap();
        let mut policy = OtlpCapturePolicy::embedded();
        policy.max_events_per_span = 1;
        policy.max_links_per_span = 1;
        let spans = map_otlp_with_policy(request, Some(&tenant()), &policy).unwrap();
        let a = serde_json::to_value(&spans[0].attributes).unwrap();
        assert_eq!(a["gen_ai_output_messages"][0]["content"], "canonical");
        assert_eq!(a["tracelane_links"].as_array().unwrap().len(), 1);
        assert_eq!(a["tracelane_attrs_dropped"]["reasons"]["cap"], 2);
    }

    #[test]
    fn message_event_variants_fold_and_unknown_prompt_families_never_pass_raw() {
        use opentelemetry_proto::tonic::trace::v1::span::Event;
        for (name, field) in [
            ("gen_ai.user.message", "gen_ai_input_messages"),
            ("gen_ai.system.message", "gen_ai_system_instructions"),
            ("gen_ai.tool.message", "gen_ai_input_messages"),
            ("gen_ai.assistant.message", "gen_ai_output_messages"),
            ("gen_ai.choice", "gen_ai_output_messages"),
        ] {
            let mut proto = sample_span();
            proto.events = vec![Event {
                name: name.into(),
                attributes: vec![kv_str("body", "private body")],
                ..Default::default()
            }];
            let spans =
                decode_otlp_protobuf(&wrap_in_request(proto, vec![]), Some(&tenant())).unwrap();
            assert_eq!(
                serde_json::to_value(&spans[0].attributes).unwrap()[field][0]["content"],
                "private body"
            );
        }
        let mut proto = sample_span();
        proto.events = vec![
            Event {
                name: "gen_ai.client.inference.operation.details".into(),
                attributes: vec![
                    kv_str("gen_ai.input.messages", r#"[{"content":"in"}]"#),
                    kv_str("gen_ai.output.messages", r#"[{"content":"out"}]"#),
                ],
                ..Default::default()
            },
            Event {
                name: "custom".into(),
                attributes: vec![
                    kv_str("custom.prompt_template", "never store raw"),
                    kv_str("custom.label", "allowed"),
                ],
                ..Default::default()
            },
        ];
        let mut spans =
            decode_otlp_protobuf(&wrap_in_request(proto, vec![]), Some(&tenant())).unwrap();
        super::super::content::apply_capture(
            &mut spans[0],
            &super::super::content::CaptureHalves {
                input: true,
                output: true,
                max_field_bytes: 1000,
            },
        );
        let a = serde_json::to_value(&spans[0].attributes).unwrap();
        assert_eq!(a["gen_ai_input_messages"][0]["content"], "in");
        assert_eq!(a["gen_ai_output_messages"][0]["content"], "out");
        assert!(!a.to_string().contains("never store raw"));
        assert_eq!(
            a["tracelane_events"][0]["attributes"]["custom.label"],
            "allowed"
        );
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

    /// B-232: the key the tool-analytics SQL reads must come out of the decoder under
    /// EXACTLY that name in the serialized attributes JSON — the flatten is what makes a
    /// dotted key survive, so the assertion is on the JSON, not on `extra`.
    #[test]
    fn b232_tool_name_reaches_the_attributes_json_under_the_key_the_sql_reads() {
        let a = build_attributes(&[kv_str("gen_ai.tool.name", "web_search")]);
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(j["gen_ai.tool.name"], "web_search");

        // OpenInference spelling maps to the canonical key.
        let a = build_attributes(&[kv_str("tool.name", "calculator")]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.tool.name"],
            "calculator"
        );

        // Canonical wins over the alias regardless of order.
        let a = build_attributes(&[
            kv_str("tool.name", "alias"),
            kv_str("gen_ai.tool.name", "canonical"),
        ]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.tool.name"],
            "canonical"
        );
        let a = build_attributes(&[
            kv_str("gen_ai.tool.name", "canonical"),
            kv_str("tool.name", "alias"),
        ]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.tool.name"],
            "canonical"
        );

        // Falsification arm: an unmapped key is still dropped, so the test above is
        // measuring the arm, not a general pass-through.
        let a = build_attributes(&[kv_str("tool.description", "x")]);
        assert!(
            serde_json::to_value(&a)
                .unwrap()
                .get("tool.description")
                .is_none()
        );
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

    // ── PLT-46: Claude Code's OTLP spellings alias onto the canonical GenAI
    // semconv fields, and the canonical key wins regardless of attribute order. ──

    fn kv_double(key: &str, val: f64) -> ProtoKeyValue {
        ProtoKeyValue {
            key: key.into(),
            value: Some(ProtoAnyValue {
                value: Some(ProtoValue::DoubleValue(val)),
            }),
        }
    }

    #[test]
    fn plt46_session_id_alias_maps_to_conversation_id_and_canonical_wins() {
        // Alias alone.
        let a = build_attributes(&[kv_str("session.id", "sess-1")]);
        assert_eq!(a.gen_ai_conversation_id.as_deref(), Some("sess-1"));

        // Canonical wins, alias first.
        let a = build_attributes(&[
            kv_str("session.id", "alias"),
            kv_str("gen_ai.conversation.id", "canonical"),
        ]);
        assert_eq!(a.gen_ai_conversation_id.as_deref(), Some("canonical"));

        // Canonical wins, canonical first.
        let a = build_attributes(&[
            kv_str("gen_ai.conversation.id", "canonical"),
            kv_str("session.id", "alias"),
        ]);
        assert_eq!(a.gen_ai_conversation_id.as_deref(), Some("canonical"));
    }

    /// `OBS-20`. The end-user alias table, and the property that matters is that
    /// the CANONICAL spelling wins in EITHER arrival order — attribute order on
    /// the wire is not something a producer guarantees.
    #[test]
    fn obs20_end_user_aliases_map_to_user_id_and_canonical_wins_either_order() {
        // The canonical spelling — simultaneously OTel's registry attribute,
        // OpenInference's reserved key, and one of Langfuse's two.
        let a = build_attributes(&[kv_str("user.id", "u_1")]);
        assert_eq!(a.user_id.as_deref(), Some("u_1"));

        // Each alias alone.
        for k in ["enduser.id", "enduser.pseudo.id", "langfuse.user.id"] {
            let a = build_attributes(&[kv_str(k, "u_alias")]);
            assert_eq!(a.user_id.as_deref(), Some("u_alias"), "alias {k} dropped");
        }

        // Canonical wins, alias first.
        let a = build_attributes(&[
            kv_str("enduser.id", "alias"),
            kv_str("user.id", "canonical"),
        ]);
        assert_eq!(a.user_id.as_deref(), Some("canonical"));

        // Canonical wins, canonical first.
        let a = build_attributes(&[
            kv_str("user.id", "canonical"),
            kv_str("enduser.id", "alias"),
        ]);
        assert_eq!(a.user_id.as_deref(), Some("canonical"));
    }

    /// `OBS-20`. The bound is applied AT THE DECODER, not left to a later layer.
    ///
    /// An OTLP producer is not a trusted source, and this is the seam where an
    /// unbounded attribute would otherwise reach a span. Over-length is DROPPED,
    /// never truncated — a truncated id silently attributes one person's traces
    /// to another.
    #[test]
    fn obs20_an_over_length_end_user_id_is_dropped_at_the_otlp_boundary() {
        let long = "x".repeat(257);
        let a = build_attributes(&[kv_str("user.id", &long)]);
        assert_eq!(a.user_id, None, "an over-length id must be dropped");

        let at_cap = "x".repeat(256);
        let a = build_attributes(&[kv_str("user.id", &at_cap)]);
        assert_eq!(a.user_id.as_deref(), Some(at_cap.as_str()));

        // Whitespace-only is absence, not an id.
        let a = build_attributes(&[kv_str("user.id", "   ")]);
        assert_eq!(a.user_id, None);
    }

    /// `OBS-20` / CLAUDE.md §17. The decoder's catch-all is EMPTY — an unmapped
    /// attribute is dropped, not stashed in `extra`. `build_attributes`' own doc
    /// comment claimed the opposite for months, and that false comment is
    /// precisely why `user.id` needed an explicit arm rather than a read-side
    /// lookup into `extra`.
    ///
    /// This pins the real behaviour so the comment cannot drift back.
    #[test]
    fn an_unmapped_attribute_is_dropped_not_swept_into_extra() {
        let a = build_attributes(&[kv_str("totally.unmapped.key", "v")]);
        assert!(
            a.extra.is_empty(),
            "unmapped attributes are DROPPED; extra was {:?}",
            a.extra
        );
    }

    #[test]
    fn plt46_token_aliases_map_to_canonical_fields_and_canonical_wins() {
        // All four Claude Code token spellings, alias alone.
        let a = build_attributes(&[
            kv_int("input_tokens", 11),
            kv_int("output_tokens", 22),
            kv_int("cache_read_tokens", 33),
            kv_int("cache_creation_tokens", 44),
        ]);
        assert_eq!(a.gen_ai_usage_input_tokens, Some(11));
        assert_eq!(a.gen_ai_usage_output_tokens, Some(22));
        assert_eq!(a.gen_ai_usage_cache_read_input_tokens, Some(33));
        assert_eq!(a.gen_ai_usage_cache_creation_input_tokens, Some(44));

        // Canonical wins, alias first.
        let a = build_attributes(&[
            kv_int("input_tokens", 7),
            kv_int("gen_ai.usage.input_tokens", 5),
        ]);
        assert_eq!(a.gen_ai_usage_input_tokens, Some(5));
        // Canonical wins, canonical first.
        let a = build_attributes(&[
            kv_int("gen_ai.usage.input_tokens", 5),
            kv_int("input_tokens", 7),
        ]);
        assert_eq!(a.gen_ai_usage_input_tokens, Some(5));

        let a = build_attributes(&[
            kv_int("output_tokens", 7),
            kv_int("gen_ai.usage.output_tokens", 5),
        ]);
        assert_eq!(a.gen_ai_usage_output_tokens, Some(5));

        let a = build_attributes(&[
            kv_int("cache_read_tokens", 7),
            kv_int("gen_ai.usage.cache_read.input_tokens", 5),
        ]);
        assert_eq!(a.gen_ai_usage_cache_read_input_tokens, Some(5));

        let a = build_attributes(&[
            kv_int("cache_creation_tokens", 7),
            kv_int("gen_ai.usage.cache_creation.input_tokens", 5),
        ]);
        assert_eq!(a.gen_ai_usage_cache_creation_input_tokens, Some(5));
    }

    #[test]
    fn plt46_tool_name_alias_reaches_the_attributes_json_and_canonical_wins() {
        let a = build_attributes(&[kv_str("tool_name", "Bash")]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.tool.name"],
            "Bash"
        );

        // Canonical wins, alias first.
        let a = build_attributes(&[
            kv_str("tool_name", "alias"),
            kv_str("gen_ai.tool.name", "canonical"),
        ]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.tool.name"],
            "canonical"
        );
        // Canonical wins, canonical first.
        let a = build_attributes(&[
            kv_str("gen_ai.tool.name", "canonical"),
            kv_str("tool_name", "alias"),
        ]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.tool.name"],
            "canonical"
        );
    }

    #[test]
    fn plt46_ttft_ms_alias_converts_milliseconds_to_seconds_and_canonical_wins() {
        // Claude Code's `ttft_ms` is milliseconds; the canonical column is seconds.
        let a = build_attributes(&[kv_int("ttft_ms", 234)]);
        assert_eq!(a.gen_ai_response_time_to_first_chunk, Some(0.234));

        // Canonical (already seconds) wins over the alias, either order — and is
        // NOT re-divided by 1000.
        let a = build_attributes(&[
            kv_int("ttft_ms", 9999),
            kv_double("gen_ai.response.time_to_first_chunk", 0.5),
        ]);
        assert_eq!(a.gen_ai_response_time_to_first_chunk, Some(0.5));
        let a = build_attributes(&[
            kv_double("gen_ai.response.time_to_first_chunk", 0.5),
            kv_int("ttft_ms", 9999),
        ]);
        assert_eq!(a.gen_ai_response_time_to_first_chunk, Some(0.5));
    }

    #[test]
    fn plt46_model_alias_fills_request_model_only_when_canonical_absent() {
        // No canonical key present → alias fills the field.
        let a = build_attributes(&[kv_str("model", "claude-sonnet-4-5-20250929")]);
        assert_eq!(
            a.gen_ai_request_model.as_deref(),
            Some("claude-sonnet-4-5-20250929")
        );

        // Canonical present → alias never overwrites it, either order.
        let a = build_attributes(&[
            kv_str("model", "alias-model"),
            kv_str("gen_ai.request.model", "canonical-model"),
        ]);
        assert_eq!(a.gen_ai_request_model.as_deref(), Some("canonical-model"));
        let a = build_attributes(&[
            kv_str("gen_ai.request.model", "canonical-model"),
            kv_str("model", "alias-model"),
        ]);
        assert_eq!(a.gen_ai_request_model.as_deref(), Some("canonical-model"));
    }

    // ── OBS-49: agent identity for multi-agent swimlanes ────────────────────

    #[test]
    fn obs49_gen_ai_agent_id_reaches_the_attributes_json() {
        let a = build_attributes(&[kv_str("gen_ai.agent.id", "a1f9")]);
        assert_eq!(serde_json::to_value(&a).unwrap()["gen_ai.agent.id"], "a1f9");
    }

    #[test]
    fn obs49_agent_id_alias_reaches_the_attributes_json_and_canonical_wins() {
        // Alias alone.
        let a = build_attributes(&[kv_str("agent_id", "researcher-1")]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.agent.id"],
            "researcher-1"
        );

        // Canonical wins, alias first.
        let a = build_attributes(&[
            kv_str("agent_id", "alias"),
            kv_str("gen_ai.agent.id", "canonical"),
        ]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.agent.id"],
            "canonical"
        );
        // Canonical wins, canonical first.
        let a = build_attributes(&[
            kv_str("gen_ai.agent.id", "canonical"),
            kv_str("agent_id", "alias"),
        ]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.agent.id"],
            "canonical"
        );
    }

    #[test]
    fn obs49_parent_agent_id_reaches_the_attributes_json_under_the_dotted_key() {
        let a = build_attributes(&[kv_str("parent_agent_id", "planner-0")]);
        assert_eq!(
            serde_json::to_value(&a).unwrap()["gen_ai.agent.parent_id"],
            "planner-0"
        );
    }
}

#[cfg(test)]
#[path = "openinference_tests.rs"]
mod openinference_tests;
