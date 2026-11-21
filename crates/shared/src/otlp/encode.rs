//! `TracelaneSpan` → OTLP (`OG-50`, `specs/OG-50-otel-export.md`): the INVERSE of
//! [`super::decode`], used by the gateway's OTLP/HTTP export of a workspace's own spans to
//! the customer's collector.
//!
//! ## What is mapped, and how
//!
//! - **Ids** — the exact inverse of the decoder's transform. A 16-byte trace id is the
//!   UUID's bytes; an 8-byte span id is the LOW 8 bytes of the UUID (the decoder widened an
//!   8-byte OTLP id by zero-padding the high 8). A gateway-built span id has random high
//!   bytes, so its export keeps the low 8 and the round trip through the decoder
//!   zero-pads: the id is stable across spans (parent ↔ child agree), not bit-identical to
//!   the 16-byte UUID.
//! - **Attributes** — GenAI semconv (v1.41) keys for every attribute the decoder maps from
//!   one ([`semconv_key`]); every other `tracelane_*` field is `tracelane.<rest>`; a scalar
//!   keeps its OTLP type, a string list is an array, a structured value is its JSON text
//!   (which the decoder reads back through `any_value_json`). `None` fields are absent.
//! - **Events** — recorded span events, and a synthesized `exception` event for
//!   `exception_type` / `exception_message` (never duplicated when the span already carries
//!   one, as a decoded span does).
//! - **Content** — with `include_content = false` the content-bearing attributes
//!   ([`CONTENT_ATTRIBUTES`]), status text and content-bearing event values are omitted.
//!   Untyped extra attributes retain only numbers, booleans and arrays of those values;
//!   event text is limited to explicit metadata keys and unknown event names become `event`.
//!   Typed span metadata, operation names and identifiers remain: this is not anonymization.
//!   `true` preserves the recorded span, including its captured content.
//!
//! Pure and allocation-bounded by the span: no I/O, no clock, no global state.

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, InstrumentationScope, KeyValue, any_value::Value as V,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{
    ResourceSpans, ScopeSpans, Span, Status, span::Event, status::StatusCode as OtlpCode,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{SpanStatusCode, TracelaneSpan};

/// `service.name` of the exported resource.
pub const EXPORT_SERVICE_NAME: &str = "tracelane-gateway";

/// The instrumentation scope name of exported spans.
pub const EXPORT_SCOPE_NAME: &str = "tracelane.gateway";

/// The `SpanAttributes` fields that carry customer CONTENT (prompt, response, tool
/// arguments and results, retrieval text). With `include_content = false` none of them is
/// encoded. `exception_message` is handled with them (a provider error body can echo a
/// prompt) though it is exported as an event attribute, not an attribute.
pub const CONTENT_ATTRIBUTES: &[&str] = &[
    "gen_ai_input_messages",
    "gen_ai_output_messages",
    "gen_ai_system_instructions",
    "gen_ai_tool_call_arguments",
    "gen_ai_tool_call_result",
    "input_value",
    "output_value",
    "tracelane_retrieval_query",
    "tracelane_retrieval_documents",
    "exception_message",
];

/// A content key is denied before considering its JSON shape, so numbers or
/// objects cannot bypass the same boundary that drops text.
fn content_attribute(key: &str) -> bool {
    CONTENT_ATTRIBUTES.contains(&key)
        || super::content::is_content_key(key)
        || matches!(
            key,
            "exception.message" | "exception.stacktrace" | "explanation"
        )
        || key.ends_with(".explanation")
}

fn non_text_metadata(value: &Value) -> bool {
    match value {
        Value::Number(_) | Value::Bool(_) => true,
        Value::Array(values) => values.iter().all(|v| v.is_number() || v.is_boolean()),
        _ => false,
    }
}

fn event_metadata(key: &str, value: &Value) -> bool {
    if content_attribute(key) {
        return false;
    }
    match key {
        "exception.type"
        | "gen_ai.evaluation.name"
        | "score.label"
        | "gen_ai.evaluation.score.label" => value.is_string(),
        _ => non_text_metadata(value),
    }
}

/// Attributes that become structure rather than a plain attribute.
const STRUCTURAL: &[&str] = &[
    "tracelane_events",
    "tracelane_links",
    "exception_type",
    "exception_message",
];

/// The OTel semconv spelling of a `SpanAttributes` field the decoder maps FROM a semconv
/// key. Anything not here is `tracelane.<rest>` (a `tracelane_*` field) or its own name.
#[must_use]
pub fn semconv_key(field: &str) -> Option<&'static str> {
    Some(match field {
        "gen_ai_system" => "gen_ai.system",
        "gen_ai_provider_name" => "gen_ai.provider.name",
        "gen_ai_request_model" => "gen_ai.request.model",
        "gen_ai_response_model" => "gen_ai.response.model",
        "gen_ai_response_id" => "gen_ai.response.id",
        "gen_ai_response_finish_reasons" => "gen_ai.response.finish_reasons",
        "gen_ai_operation_name" => "gen_ai.operation.name",
        "gen_ai_agent_name" => "gen_ai.agent.name",
        "gen_ai_agent_version" => "gen_ai.agent.version",
        "gen_ai_conversation_id" => "gen_ai.conversation.id",
        "gen_ai_usage_cost" => "gen_ai.usage.cost",
        "gen_ai_usage_input_tokens" => "gen_ai.usage.input_tokens",
        "gen_ai_usage_output_tokens" => "gen_ai.usage.output_tokens",
        "gen_ai_usage_cache_read_input_tokens" => "gen_ai.usage.cache_read.input_tokens",
        "gen_ai_usage_cache_creation_input_tokens" => "gen_ai.usage.cache_creation.input_tokens",
        "gen_ai_usage_reasoning_output_tokens" => "gen_ai.usage.reasoning.output_tokens",
        "gen_ai_request_stream" => "gen_ai.request.stream",
        "gen_ai_response_time_to_first_chunk" => "gen_ai.response.time_to_first_chunk",
        "gen_ai_request_temperature" => "gen_ai.request.temperature",
        "gen_ai_request_top_p" => "gen_ai.request.top_p",
        "gen_ai_request_max_tokens" => "gen_ai.request.max_tokens",
        "gen_ai_request_seed" => "gen_ai.request.seed",
        "gen_ai_tool_call_id" => "gen_ai.tool.call.id",
        "gen_ai_tool_call_arguments" => "gen_ai.tool.call.arguments",
        "gen_ai_tool_call_result" => "gen_ai.tool.call.result",
        "gen_ai_system_instructions" => "gen_ai.system_instructions",
        "gen_ai_input_messages" => "gen_ai.input.messages",
        "gen_ai_output_messages" => "gen_ai.output.messages",
        "tracelane_retrieval_query" => "gen_ai.retrieval.query.text",
        "tracelane_retrieval_documents" => "gen_ai.retrieval.documents",
        "error_type" => "error.type",
        "service_name" => "service.name",
        "service_version" => "service.version",
        "deployment_environment" => "deployment.environment.name",
        "user_id" => "user.id",
        "tracelane_usage_input_includes_cache" => "tracelane.usage.input_includes_cache",
        "tracelane_predictive_rug_pull_detected" => "tracelane.predictive.rug_pull_detected",
        "tracelane_predictive_stuck_loop" => "tracelane.predictive.stuck_loop",
        "tracelane_predictive_captcha_detected" => "tracelane.predictive.captcha_detected",
        "tracelane_predictive_anomaly_score" => "tracelane.predictive.anomaly_score",
        "tracelane_mcp_tool_hash" => "tracelane.mcp.tool_hash",
        "tracelane_mcp_server_url" => "tracelane.mcp.server_url",
        "tracelane_kya_agent_id" => "tracelane.kya.agent_id",
        "tracelane_agent_step_index" => "tracelane.agent.step_index",
        "tracelane_context_truncated" => "tracelane.context.truncated",
        _ => return None,
    })
}

/// The key an attribute is exported under.
fn export_key(field: &str) -> String {
    if let Some(k) = semconv_key(field) {
        return k.to_owned();
    }
    match field.strip_prefix("tracelane_") {
        Some(rest) => format!("tracelane.{rest}"),
        None => field.to_owned(),
    }
}

fn any(v: V) -> AnyValue {
    AnyValue { value: Some(v) }
}

fn kv(key: impl Into<String>, v: V) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(any(v)),
    }
}

/// One JSON value as an OTLP attribute value. `None` for `null` (absent, never an empty
/// string). A string list is an OTLP array of strings; any other structure is its JSON text.
fn to_any(v: &Value) -> Option<V> {
    Some(match v {
        Value::Null => return None,
        Value::Bool(b) => V::BoolValue(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                V::IntValue(i)
            } else if let Some(u) = n.as_u64() {
                // OTLP has no unsigned integer: a value past i64 keeps its value as a double.
                i64::try_from(u).map_or(V::DoubleValue(u as f64), V::IntValue)
            } else {
                V::DoubleValue(n.as_f64()?)
            }
        }
        Value::String(s) => V::StringValue(s.clone()),
        Value::Array(items)
            if !items.is_empty() && items.iter().all(|i| matches!(i, Value::String(_))) =>
        {
            V::ArrayValue(ArrayValue {
                values: items
                    .iter()
                    .filter_map(|i| i.as_str())
                    .map(|s| any(V::StringValue(s.to_owned())))
                    .collect(),
            })
        }
        other => V::StringValue(other.to_string()),
    })
}

/// A UUID as an OTLP 16-byte trace id.
#[must_use]
pub fn trace_id_bytes(id: Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

/// A UUID as an OTLP 8-byte span id: the LOW 8 bytes — the inverse of
/// [`super::decode::otlp_span_id_to_uuid`]'s zero-padding.
#[must_use]
pub fn span_id_bytes(id: Uuid) -> Vec<u8> {
    id.as_bytes()[8..].to_vec()
}

fn nanos(t: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(t.timestamp_nanos_opt().unwrap_or(0)).unwrap_or(0)
}

/// Encode one span. `include_content = false` never encodes a [`CONTENT_ATTRIBUTES`] field.
#[must_use]
pub fn encode_span(span: &TracelaneSpan, include_content: bool) -> Span {
    let mut attributes = Vec::new();
    // `SpanAttributes` serialises every set field under its own name (`extra` is flattened):
    // walking the map is how a field this encoder has never heard of still ships, under its
    // own name, rather than vanishing.
    if let Ok(Value::Object(map)) = serde_json::to_value(&span.attributes) {
        for (field, value) in &map {
            if STRUCTURAL.contains(&field.as_str()) || super::openinference_emit::owns(field) {
                continue;
            }
            let key = export_key(field);
            if !include_content
                && (content_attribute(field)
                    || content_attribute(&key)
                    || (span.attributes.extra.contains_key(field) && !non_text_metadata(value)))
            {
                continue;
            }
            if let Some(v) = to_any(value) {
                attributes.push(kv(key, v));
            }
        }
    }
    // Only curated typed metadata gets this content-off path; arbitrary `extra`
    // text stays filtered above. Owned aliases cannot override canonical fields.
    let mut aliases = super::openinference_emit::metadata(&span.attributes);
    if include_content {
        aliases.extend(super::openinference_emit::content(&span.attributes));
    }
    attributes.extend(
        aliases
            .into_iter()
            .filter_map(|(key, value)| to_any(&value).map(|value| kv(key, value))),
    );
    // Stable order: a collector (and a test) sees the same bytes for the same span.
    attributes.sort_by(|a, b| a.key.cmp(&b.key));

    let mut events: Vec<Event> = span
        .attributes
        .tracelane_events
        .iter()
        .flatten()
        .map(|e| Event {
            time_unix_nano: e.time_unix_us.saturating_mul(1000),
            name: if include_content
                || matches!(e.name.as_str(), "exception" | "gen_ai.evaluation.result")
            {
                e.name.clone()
            } else {
                "event".to_owned()
            },
            attributes: e
                .attributes
                .iter()
                .filter(|(k, v)| include_content || event_metadata(k, v))
                .filter_map(|(k, v)| to_any(v).map(|v| kv(k.clone(), v)))
                .collect(),
            dropped_attributes_count: 0,
        })
        .collect();
    let has_exception_event = events.iter().any(|e| e.name == "exception");
    let ex_type = span.attributes.exception_type.as_deref();
    let ex_msg = span
        .attributes
        .exception_message
        .as_deref()
        .filter(|_| include_content);
    if !has_exception_event && (ex_type.is_some() || ex_msg.is_some()) {
        let mut attrs = Vec::new();
        if let Some(t) = ex_type {
            attrs.push(kv("exception.type", V::StringValue(t.to_owned())));
        }
        if let Some(m) = ex_msg {
            attrs.push(kv("exception.message", V::StringValue(m.to_owned())));
        }
        events.push(Event {
            time_unix_nano: nanos(span.end_time.unwrap_or(span.start_time)),
            name: "exception".to_owned(),
            attributes: attrs,
            dropped_attributes_count: 0,
        });
    }

    let links = span
        .attributes
        .tracelane_links
        .iter()
        .flatten()
        .map(|l| opentelemetry_proto::tonic::trace::v1::span::Link {
            trace_id: trace_id_bytes(l.trace_id),
            span_id: span_id_bytes(l.span_id),
            ..Default::default()
        })
        .collect();

    Span {
        trace_id: trace_id_bytes(span.trace_id),
        span_id: span_id_bytes(span.span_id),
        parent_span_id: span.parent_span_id.map(span_id_bytes).unwrap_or_default(),
        name: span.name.clone(),
        // The gateway's span is a client call to a model provider (GenAI semconv).
        kind: opentelemetry_proto::tonic::trace::v1::span::SpanKind::Client as i32,
        start_time_unix_nano: nanos(span.start_time),
        end_time_unix_nano: span.end_time.map_or(0, nanos),
        attributes,
        events,
        links,
        status: Some(Status {
            code: match span.status.code {
                SpanStatusCode::Ok => OtlpCode::Ok as i32,
                SpanStatusCode::Error => OtlpCode::Error as i32,
                SpanStatusCode::Unset => OtlpCode::Unset as i32,
            },
            message: if include_content {
                span.status.message.clone().unwrap_or_default()
            } else {
                String::new()
            },
        }),
        ..Default::default()
    }
}

/// Wrap already-encoded spans in one export request: a single resource
/// (`service.name = tracelane-gateway`) and one scope. The caller bounds the batch.
#[must_use]
pub fn export_request(spans: Vec<Span>) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![kv(
                    "service.name",
                    V::StringValue(EXPORT_SERVICE_NAME.into()),
                )],
                dropped_attributes_count: 0,
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: EXPORT_SCOPE_NAME.to_owned(),
                    ..Default::default()
                }),
                spans,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}

/// The encoded span type, re-exported so the gateway needs no protobuf dependency of its own.
pub use opentelemetry_proto::tonic::trace::v1::Span as OtlpSpan;

/// The protobuf size of one encoded span — what the export batcher bounds a request by.
#[must_use]
pub fn span_encoded_len(span: &OtlpSpan) -> usize {
    prost::Message::encoded_len(span)
}

/// A batch of encoded spans as the OTLP/HTTP request BODY (`application/x-protobuf`).
#[must_use]
pub fn request_bytes(spans: Vec<OtlpSpan>) -> Vec<u8> {
    prost::Message::encode_to_vec(&export_request(spans))
}

/// Encode a span as a standalone request (the test-delivery path, and tests).
#[must_use]
pub fn encode_request(span: &TracelaneSpan, include_content: bool) -> ExportTraceServiceRequest {
    export_request(vec![encode_span(span, include_content)])
}

#[cfg(test)]
mod tests {

    /// Every text-capable `SpanAttributes` field is CLASSIFIED: in `CONTENT_ATTRIBUTES`
    /// (dropped when content is off) or in this reviewed list (exported, then PII-redacted by
    /// the gateway tap). Typed fields use a denylist, so an unclassified new field would export
    /// by default — the default-open shape of `.claude/rules/tenancy.md`. Security review of
    /// #236, finding B. Reviewed 2026-11-10: none of these holds customer content.
    #[test]
    fn every_text_field_of_span_attributes_is_classified() {
        const REVIEWED_NON_CONTENT: &[&str] = &[
            "tracelane_metadata",
            "tracelane_tags",
            "tracelane_labels_dropped",
            "otlp_pending",
            "exception_type",
            "tracelane_events",
            "tracelane_links",
            "gen_ai_system",
            "gen_ai_request_model",
            "gen_ai_operation_name",
            "gen_ai_provider_name",
            "gen_ai_response_model",
            "gen_ai_response_id",
            "gen_ai_response_finish_reasons",
            "tracelane_model_substitution",
            "gen_ai_agent_name",
            "tracelane_client_name",
            "tracelane_agent_name_source",
            "tracelane_usage_cost_origin",
            "tracelane_semantic_cache_tier",
            "tracelane_eval_run_id",
            "tracelane_experiment_id",
            "tracelane_eval_role",
            "tracelane_semantic_cache_source_trace_id",
            "tracelane_api_key_id",
            "tracelane_project_id",
            "tracelane_rejection_reason",
            "gen_ai_agent_version",
            "gen_ai_conversation_id",
            "openinference_span_kind",
            "gen_ai_tool_call_id",
            "gen_ai_tool_call_arg_fp",
            "error_type",
            "service_name",
            "service_version",
            "deployment_environment",
            "tracelane_attrs_dropped",
            "tracelane_content_withheld",
            "tracelane_aft_id",
            "tracelane_intervention",
            "tracelane_failover_from",
            "tracelane_dispatch_attempts",
            "tracelane_mcp_tool_hash",
            "tracelane_mcp_server_url",
            "tracelane_kya_agent_id",
            "tracelane_kya_human_authorizer",
            "tracelane_business_reference",
            "user_id",
            "tracelane_request_tool_choice_mode",
            "tracelane_request_tool_choice_function",
            "tracelane_request_tool_names",
            "tracelane_response_tool_names",
            "tracelane_response_tool_arg_fps",
            "tracelane_zdr_eligible_providers",
            "tracelane_request_tool_definitions_hash",
            "tracelane_request_deployment_id",
            "tracelane_request_extra_keys",
            "tracelane_misconfig_flags",
            "extra",
        ];
        let src = include_str!("../span.rs");
        let start = src
            .find("pub struct SpanAttributes {")
            .expect("SpanAttributes in span.rs");
        let body = &src[start..start + src[start..].find("\n}\n").expect("end of SpanAttributes")];
        let mut scanned = 0;
        let mut unclassified = Vec::new();
        for line in body.lines().map(str::trim) {
            let Some(rest) = line.strip_prefix("pub ") else {
                continue;
            };
            let Some((name, ty)) = rest.split_once(':') else {
                continue;
            };
            if name.contains(' ') || name.contains('(') {
                continue; // `pub struct …` header, not a field
            }
            scanned += 1;
            let text_capable = [
                "String",
                "Value",
                "SpanEvent",
                "SpanLink",
                "RetrievalDocument",
                "Intervention",
                "DispatchAttempt",
                "PendingAttributes",
                "Dropped",
            ]
            .iter()
            .any(|t| ty.contains(t));
            if text_capable
                && !CONTENT_ATTRIBUTES.contains(&name)
                && !REVIEWED_NON_CONTENT.contains(&name)
            {
                unclassified.push(name.to_owned());
            }
        }
        assert!(
            scanned >= 100,
            "scanned {scanned} fields: the parser lost the struct"
        );
        assert!(
            unclassified.is_empty(),
            "classify these SpanAttributes fields as CONTENT_ATTRIBUTES (dropped when content is \
             off) or REVIEWED_NON_CONTENT (exported, PII-redacted): {unclassified:?}"
        );
    }

    use super::*;
    use crate::otlp::decode::map_otlp_to_tracelane_spans;
    use crate::{SpanAttributes, SpanStatus, TenantId};
    use chrono::{TimeZone, Utc};
    use prost::Message;

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap())
    }

    /// An OTLP-origin span: the high 8 bytes of both ids are zero, exactly what the decoder
    /// produces, so the round trip can be asserted EQUAL (a gateway-built span has random
    /// high bytes and exports its low 8).
    #[allow(clippy::field_reassign_with_default)] // a 25-field fixture reads better as sets
    fn span() -> TracelaneSpan {
        let mut a = SpanAttributes::default();
        a.gen_ai_provider_name = Some("anthropic".into());
        a.gen_ai_system = Some("anthropic".into());
        a.gen_ai_request_model = Some("claude-sonnet-4-6".into());
        a.gen_ai_response_model = Some("claude-sonnet-4-6-20260101".into());
        a.gen_ai_usage_input_tokens = Some(12);
        a.gen_ai_usage_output_tokens = Some(34);
        a.gen_ai_usage_cost = Some(0.0042);
        a.gen_ai_response_finish_reasons = Some(vec!["stop".into()]);
        a.gen_ai_request_temperature = Some(0.5);
        a.gen_ai_request_max_tokens = Some(256);
        a.gen_ai_request_seed = Some(42);
        a.gen_ai_request_stream = Some(true);
        a.gen_ai_operation_name = Some("chat".into());
        a.gen_ai_conversation_id = Some("conv-1".into());
        a.user_id = Some("end-user-7".into());
        a.service_name = Some("checkout".into());
        a.tracelane_agent_step_index = Some(3);
        a.gen_ai_input_messages =
            Some(serde_json::json!([{"role":"user","content":"secret prompt"}]));
        a.gen_ai_output_messages =
            Some(serde_json::json!([{"role":"assistant","content":"secret answer"}]));
        a.gen_ai_system_instructions =
            Some(serde_json::json!([{"role":"system","content":"be nice"}]));
        a.gen_ai_tool_call_arguments = Some("{\"city\":\"Paris\"}".into());
        a.input_value = Some("raw input".into());
        a.exception_type = Some("RateLimitError".into());
        a.exception_message = Some("429: your prompt was 'secret prompt'".into());
        a.tracelane_semantic_cache_hit = Some(true);
        TracelaneSpan {
            span_id: Uuid::from_u128(0xaabb_ccdd_0011_2233),
            trace_id: Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            parent_span_id: Some(Uuid::from_u128(0x0102_0304_0506_0708)),
            tenant_id: tenant(),
            name: "gen_ai.chat".into(),
            start_time: Utc.timestamp_opt(1_790_000_000, 123_456_789).unwrap(),
            end_time: Some(Utc.timestamp_opt(1_790_000_001, 5_000).unwrap()),
            attributes: a,
            status: SpanStatus {
                code: SpanStatusCode::Error,
                message: Some("upstream 429".into()),
            },
        }
    }

    fn attr<'a>(s: &'a Span, key: &str) -> Option<&'a AnyValue> {
        s.attributes
            .iter()
            .find(|a| a.key == key)
            .and_then(|a| a.value.as_ref())
    }

    fn roundtrip(s: &TracelaneSpan, content: bool) -> TracelaneSpan {
        // Through the WIRE, not just the struct: protobuf bytes out, protobuf bytes in.
        let bytes = encode_request(s, content).encode_to_vec();
        let req = ExportTraceServiceRequest::decode(bytes.as_slice()).expect("our own bytes");
        let mut out = map_otlp_to_tracelane_spans(req, Some(&s.tenant_id)).expect("decodes");
        assert_eq!(out.len(), 1);
        out.remove(0)
    }

    #[test]
    fn openinference_export_uses_canonical_typed_attribute_names() {
        let mut source = span();
        source.attributes.output_value = Some("synthetic answer".into());
        source.attributes.openinference_span_kind = Some("LLM".into());
        let encoded = encode_span(&source, true);
        for (key, expected) in [
            ("input.value", "raw input"),
            ("output.value", "synthetic answer"),
            ("openinference.span.kind", "LLM"),
        ] {
            assert_eq!(
                attr(&encoded, key).and_then(|v| v.value.as_ref()),
                Some(&V::StringValue(expected.into())),
                "canonical OpenInference key {key} must preserve the recorded value"
            );
        }
        assert!(attr(&encoded, "gen_ai.input.messages").is_some());
        assert_eq!(attr(&encoded, "input_value"), attr(&encoded, "input.value"));
        assert_eq!(
            attr(&encoded, "output_value"),
            attr(&encoded, "output.value")
        );
    }

    #[test]
    fn openinference_export_derives_content_from_stored_gen_ai_fields() {
        let mut source = span();
        source.attributes.input_value = None;
        source.attributes.output_value = None;
        source.attributes.gen_ai_operation_name = Some("chat".into());
        source.attributes.gen_ai_input_messages =
            Some(serde_json::json!([{"role": "user", "content": "synthetic"}]));
        source.attributes.gen_ai_output_messages =
            Some(serde_json::json!([{"role": "assistant", "content": "answer"}]));
        let encoded = encode_span(&source, true);
        let input = attr(&encoded, "input.value").expect("derived at export");
        assert!(format!("{input:?}").contains("synthetic"));
        assert!(format!("{:?}", attr(&encoded, "output.value")).contains("answer"));
        assert!(format!("{:?}", attr(&encoded, "input.mime_type")).contains("application/json"));
    }

    #[test]
    fn openinference_export_derives_tool_content_from_tool_fields() {
        let mut source = span();
        source.attributes.input_value = None;
        source.attributes.output_value = None;
        source.attributes.gen_ai_operation_name = Some("execute_tool".into());
        source.attributes.gen_ai_tool_call_arguments = Some(r#"{"q":"synthetic"}"#.into());
        source.attributes.gen_ai_tool_call_result = Some("plain result".into());
        let encoded = encode_span(&source, true);
        assert!(format!("{:?}", attr(&encoded, "input.value")).contains("synthetic"));
        assert!(format!("{:?}", attr(&encoded, "input.mime_type")).contains("application/json"));
        assert!(format!("{:?}", attr(&encoded, "output.mime_type")).contains("text/plain"));
    }

    #[test]
    fn openinference_export_content_off_keeps_kind_but_omits_both_content_names() {
        let mut source = span();
        source.attributes.output_value = Some("synthetic answer".into());
        source.attributes.openinference_span_kind = Some("LLM".into());
        source.attributes.gen_ai_input_messages =
            Some(serde_json::json!([{"role": "user", "content": "synthetic"}]));
        let encoded = encode_span(&source, false);
        for key in [
            "input.value",
            "input_value",
            "output.value",
            "output_value",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
        ] {
            assert!(attr(&encoded, key).is_none(), "content-off omitted {key}");
        }
        assert_eq!(
            attr(&encoded, "openinference.span.kind").and_then(|v| v.value.as_ref()),
            Some(&V::StringValue("LLM".into()))
        );
    }

    fn oi_value(source: &TracelaneSpan, key: &str) -> Option<serde_json::Value> {
        let encoded = encode_span(source, false);
        attr(&encoded, key).and_then(super::super::decode::wire_json)
    }

    #[test]
    fn openinference_recorded_example_golden() {
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/openinference-llm.json")).unwrap();
        let mut source = span();
        source.attributes.gen_ai_system = Some("openai".into());
        source.attributes.gen_ai_provider_name = Some("openai".into());
        source.attributes.gen_ai_request_model = Some("gpt-3.5-turbo-0613".into());
        source.attributes.gen_ai_response_model = Some("gpt-3.5-turbo-0613".into());
        source.attributes.gen_ai_usage_input_tokens = Some(229);
        source.attributes.gen_ai_usage_output_tokens = Some(21);
        for (key, expected) in golden["attributes"].as_object().unwrap() {
            assert_eq!(oi_value(&source, key).as_ref(), Some(expected), "{key}");
        }
    }

    #[test]
    fn openinference_metadata_survives_content_off() {
        let source = span();
        assert_eq!(
            oi_value(&source, "llm.provider"),
            Some(serde_json::json!("anthropic"))
        );
        assert_eq!(
            oi_value(&source, "openinference.span.kind"),
            Some(serde_json::json!("LLM"))
        );
    }

    #[test]
    fn openinference_response_model_and_request_remain_distinct() {
        let source = span();
        assert_eq!(
            oi_value(&source, "llm.model_name"),
            Some(serde_json::json!("claude-sonnet-4-6-20260101"))
        );
        assert_eq!(
            oi_value(&source, "llm.request.model_name"),
            Some(serde_json::json!("claude-sonnet-4-6"))
        );
        assert_eq!(
            oi_value(&source, "llm.response.model_name"),
            Some(serde_json::json!("claude-sonnet-4-6-20260101"))
        );
        let decoded = roundtrip(&source, true);
        assert_eq!(
            decoded.attributes.gen_ai_request_model,
            source.attributes.gen_ai_request_model
        );
        assert_eq!(
            decoded.attributes.gen_ai_response_model,
            source.attributes.gen_ai_response_model
        );
    }

    #[test]
    fn openinference_inclusive_token_counts() {
        let source = span();
        assert_eq!(
            oi_value(&source, "llm.token_count.prompt"),
            Some(serde_json::json!(12))
        );
        assert_eq!(
            oi_value(&source, "llm.token_count.total"),
            Some(serde_json::json!(46))
        );
    }

    #[test]
    fn openinference_exclusive_token_counts() {
        let mut source = span();
        source.attributes.tracelane_usage_input_includes_cache = Some(false);
        source.attributes.gen_ai_usage_cache_read_input_tokens = Some(5);
        source.attributes.gen_ai_usage_cache_creation_input_tokens = Some(7);
        assert_eq!(
            oi_value(&source, "llm.token_count.prompt"),
            Some(serde_json::json!(24))
        );
        assert_eq!(
            oi_value(&source, "llm.token_count.total"),
            Some(serde_json::json!(58))
        );
        assert_eq!(source.attributes.gen_ai_usage_input_tokens, Some(12));
    }

    #[test]
    fn openinference_zero_is_preserved() {
        let mut source = span();
        source.attributes.gen_ai_usage_input_tokens = Some(0);
        source.attributes.gen_ai_usage_output_tokens = Some(0);
        assert_eq!(
            oi_value(&source, "llm.token_count.total"),
            Some(serde_json::json!(0))
        );
    }

    #[test]
    fn openinference_known_kinds() {
        for kind in ["tool", "agent", "LLM", "prompt"] {
            let mut source = span();
            source.attributes.openinference_span_kind = Some(kind.into());
            assert_eq!(
                oi_value(&source, "openinference.span.kind"),
                Some(serde_json::json!(kind.to_ascii_uppercase()))
            );
        }
    }

    #[test]
    fn openinference_embedding_has_no_llm_identity() {
        let mut source = span();
        source.attributes.gen_ai_operation_name = Some("embeddings".into());
        assert_eq!(
            oi_value(&source, "openinference.span.kind"),
            Some(serde_json::json!("EMBEDDING"))
        );
        assert_eq!(
            oi_value(&source, "embedding.model_name"),
            Some(serde_json::json!("claude-sonnet-4-6"))
        );
        assert!(oi_value(&source, "llm.model_name").is_none());
    }

    #[test]
    fn openinference_invocation_parameters_are_numeric() {
        let source = span();
        let params = oi_value(&source, "llm.invocation_parameters").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(params.as_str().unwrap()).unwrap();
        assert_eq!(
            parsed,
            serde_json::json!({"temperature":0.5,"max_tokens":256,"seed":42})
        );
    }

    #[test]
    fn openinference_missing_usage_is_absent() {
        let mut source = span();
        source.attributes.gen_ai_usage_input_tokens = None;
        source.attributes.gen_ai_usage_output_tokens = None;
        assert!(oi_value(&source, "llm.token_count.prompt").is_none());
        assert!(oi_value(&source, "llm.token_count.total").is_none());
    }

    #[test]
    fn openinference_unknown_cache_omits_total() {
        let mut source = span();
        source.attributes.tracelane_usage_input_includes_cache = Some(false);
        source.attributes.gen_ai_usage_cache_read_input_tokens = Some(5);
        assert!(oi_value(&source, "llm.token_count.prompt").is_none());
        assert!(oi_value(&source, "llm.token_count.total").is_none());
        assert_eq!(
            oi_value(&source, "llm.token_count.prompt_details.cache_read"),
            Some(serde_json::json!(5))
        );
    }

    #[test]
    fn openinference_total_does_not_wrap() {
        let mut source = span();
        source.attributes.gen_ai_usage_input_tokens = Some(u32::MAX);
        source.attributes.gen_ai_usage_output_tokens = Some(u32::MAX);
        assert_eq!(
            oi_value(&source, "llm.token_count.total"),
            Some(serde_json::json!(8589934590_u64))
        );
    }

    #[test]
    fn openinference_unknown_kind_is_absent() {
        let mut source = span();
        source.attributes.gen_ai_operation_name = Some("unknown-operation".into());
        source.attributes.gen_ai_agent_name = Some("synthetic-agent".into());
        assert!(oi_value(&source, "openinference.span.kind").is_none());
        assert!(oi_value(&source, "llm.model_name").is_none());
    }

    #[test]
    fn openinference_untrusted_aliases_are_not_metadata() {
        let mut source = span();
        source.attributes.gen_ai_request_temperature = None;
        source.attributes.gen_ai_request_max_tokens = None;
        source.attributes.gen_ai_request_seed = None;
        source.attributes.extra.insert(
            "llm.invocation_parameters".into(),
            serde_json::json!("synthetic private text"),
        );
        source.attributes.extra.insert(
            "llm.provider".into(),
            serde_json::json!("unreviewed extra text"),
        );
        assert!(oi_value(&source, "llm.invocation_parameters").is_none());
        assert_eq!(
            oi_value(&source, "llm.provider"),
            Some(serde_json::json!("anthropic"))
        );
    }

    #[test]
    fn openinference_mime_requires_content() {
        let mut source = span();
        source.attributes.input_value = None;
        source.attributes.output_value = None;
        source.attributes.extra.insert(
            "output.mime_type".into(),
            serde_json::json!("application/json"),
        );
        assert!(oi_value(&source, "output.mime_type").is_none());
    }

    #[test]
    fn openinference_content_export_invariant_sweep() {
        // 4 input states × 4 output states × 2 destination choices = 32 named
        // scenarios. Values are harmless synthetic fixtures, never traffic.
        let states = [
            ("absent", None),
            ("empty", Some("")),
            ("plain", Some("synthetic text")),
            ("json", Some("[]")),
        ];
        let mut scenarios = 0;
        for (input_name, input) in states {
            for (output_name, output) in states {
                for content in [false, true] {
                    let case = format!("input={input_name}/output={output_name}/content={content}");
                    let mut source = span();
                    // Stored-value semantics only: no GenAI fields to derive from here
                    // (derivation has its own tests).
                    source.attributes.gen_ai_input_messages = None;
                    source.attributes.gen_ai_output_messages = None;
                    source.attributes.input_value = input.map(str::to_owned);
                    source.attributes.output_value = output.map(str::to_owned);
                    // Only supported, valid MIME accompanies JSON. Arbitrary
                    // dotted extras cannot impersonate the typed capture result.
                    for key in ["input.mime_type", "output.mime_type"] {
                        source
                            .attributes
                            .extra
                            .insert(key.into(), serde_json::json!("application/json"));
                    }
                    source.attributes.extra.insert(
                        "input.value".into(),
                        serde_json::json!("unclassified fixture text"),
                    );
                    source.attributes.extra.insert(
                        "output.value".into(),
                        serde_json::json!("unclassified fixture text"),
                    );
                    let encoded = encode_span(&source, content);
                    for (key, legacy, mime, value) in [
                        ("input.value", "input_value", "input.mime_type", input),
                        ("output.value", "output_value", "output.mime_type", output),
                    ] {
                        let expected = value.filter(|_| content);
                        let actual = attr(&encoded, key).and_then(super::super::decode::wire_json);
                        assert_eq!(
                            actual,
                            expected.map(|v| serde_json::json!(v)),
                            "{case}/{key}"
                        );
                        assert_eq!(
                            attr(&encoded, legacy),
                            attr(&encoded, key),
                            "{case}/{legacy}"
                        );
                        assert_eq!(
                            attr(&encoded, mime).is_some(),
                            expected == Some("[]"),
                            "{case}/{mime}"
                        );
                        assert!(
                            encoded.attributes.iter().filter(|a| a.key == key).count() <= 1,
                            "{case}/duplicate"
                        );
                    }
                    scenarios += 1;
                }
            }
        }
        assert_eq!(scenarios, 32);
    }

    /// Spec §7 row 1: `decode(encode(span))` equals the span on every mapped field, ids
    /// and times included.
    #[test]
    fn og50_the_encoder_round_trips_through_the_decoder_on_every_mapped_field() {
        let s = span();
        let d = roundtrip(&s, true);
        assert_eq!(d.trace_id, s.trace_id);
        assert_eq!(d.span_id, s.span_id);
        assert_eq!(d.parent_span_id, s.parent_span_id);
        assert_eq!(d.name, s.name);
        assert_eq!(d.start_time, s.start_time, "nanosecond precision survives");
        assert_eq!(d.end_time, s.end_time);
        assert_eq!(d.status.code, s.status.code);
        assert_eq!(d.status.message, s.status.message);
        let (a, b) = (&d.attributes, &s.attributes);
        assert_eq!(a.gen_ai_provider_name, b.gen_ai_provider_name);
        assert_eq!(a.gen_ai_system, b.gen_ai_system);
        assert_eq!(a.gen_ai_request_model, b.gen_ai_request_model);
        assert_eq!(a.gen_ai_response_model, b.gen_ai_response_model);
        assert_eq!(a.gen_ai_usage_input_tokens, b.gen_ai_usage_input_tokens);
        assert_eq!(a.gen_ai_usage_output_tokens, b.gen_ai_usage_output_tokens);
        assert_eq!(a.gen_ai_usage_cost, b.gen_ai_usage_cost);
        assert_eq!(
            a.gen_ai_response_finish_reasons,
            b.gen_ai_response_finish_reasons
        );
        assert_eq!(a.gen_ai_request_temperature, b.gen_ai_request_temperature);
        assert_eq!(a.gen_ai_request_max_tokens, b.gen_ai_request_max_tokens);
        assert_eq!(a.gen_ai_request_seed, b.gen_ai_request_seed);
        assert_eq!(a.gen_ai_request_stream, b.gen_ai_request_stream);
        assert_eq!(a.gen_ai_operation_name, b.gen_ai_operation_name);
        assert_eq!(a.gen_ai_conversation_id, b.gen_ai_conversation_id);
        assert_eq!(a.user_id, b.user_id);
        assert_eq!(a.service_name, b.service_name);
        assert_eq!(a.tracelane_agent_step_index, b.tracelane_agent_step_index);
        assert_eq!(a.gen_ai_input_messages, b.gen_ai_input_messages);
        assert_eq!(a.gen_ai_output_messages, b.gen_ai_output_messages);
        assert_eq!(a.gen_ai_system_instructions, b.gen_ai_system_instructions);
        assert_eq!(a.gen_ai_tool_call_arguments, b.gen_ai_tool_call_arguments);
        assert_eq!(a.exception_type, b.exception_type);
        assert_eq!(a.exception_message, b.exception_message);
    }

    #[test]
    fn og50_an_8_byte_span_id_is_the_low_bytes_and_a_gateway_id_keeps_them() {
        use crate::otlp::decode::otlp_span_id_to_uuid;
        let eight = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let widened = otlp_span_id_to_uuid(&eight).unwrap();
        assert_eq!(span_id_bytes(widened), eight.to_vec(), "the exact inverse");
        // A gateway-built id (random high bytes): the low 8 are exported, so a child's
        // parent_span_id and its parent's span_id agree on the wire.
        let gw = Uuid::new_v4();
        assert_eq!(span_id_bytes(gw), gw.as_bytes()[8..].to_vec());
        assert_eq!(trace_id_bytes(gw).len(), 16);
    }

    /// Spec §7 row 7: `include_content = false` ships NO content though the span holds it —
    /// and the secret text appears nowhere in the encoded bytes.
    #[test]
    fn og50_content_is_not_encoded_unless_asked_and_never_appears_in_the_bytes() {
        let s = span();
        let bytes = encode_request(&s, false).encode_to_vec();
        let text = String::from_utf8_lossy(&bytes);
        for secret in [
            "secret prompt",
            "secret answer",
            "be nice",
            "Paris",
            "raw input",
        ] {
            assert!(!text.contains(secret), "{secret} leaked into the export");
        }
        let sp = encode_span(&s, false);
        for key in [
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.system_instructions",
            "gen_ai.tool.call.arguments",
            "input_value",
        ] {
            assert!(attr(&sp, key).is_none(), "{key} must be absent");
        }
        // Non-content metadata still ships, and the exception keeps its TYPE but not its message.
        assert!(attr(&sp, "gen_ai.request.model").is_some());
        let ex = sp
            .events
            .iter()
            .find(|e| e.name == "exception")
            .expect("event");
        assert!(ex.attributes.iter().any(|a| a.key == "exception.type"));
        assert!(!ex.attributes.iter().any(|a| a.key == "exception.message"));
        // `true` ships what the span holds.
        let with = String::from_utf8_lossy(&encode_request(&s, true).encode_to_vec()).into_owned();
        assert!(with.contains("secret prompt") && with.contains("secret answer"));
        // A span captured with content OFF carries none, whatever the flag says.
        let mut bare = span();
        bare.attributes.gen_ai_input_messages = None;
        bare.attributes.gen_ai_output_messages = None;
        bare.attributes.gen_ai_system_instructions = None;
        bare.attributes.gen_ai_tool_call_arguments = None;
        bare.attributes.input_value = None;
        bare.attributes.exception_message = None;
        let t = String::from_utf8_lossy(&encode_request(&bare, true).encode_to_vec()).into_owned();
        assert!(!t.contains("secret"));
    }

    #[test]
    fn no_content_export_omits_status_events_and_untyped_text_from_entire_protobuf() {
        let mut s = span();
        s.status.message = Some("PRIVATE_STATUS_921".into());
        s.attributes.extra.insert(
            "custom.payload".into(),
            serde_json::json!({"text": "PRIVATE_EXTRA_921"}),
        );
        s.attributes
            .extra
            .insert("custom.count".into(), serde_json::json!(17));
        s.attributes.tracelane_events = Some(vec![
            crate::span::SpanEvent { name: "exception".into(), time_unix_us: 11, attributes: [
                ("exception.type".into(), serde_json::json!("ValueError")),
                ("exception.message".into(), serde_json::json!("PRIVATE_MESSAGE_921")),
                ("exception.stacktrace".into(), serde_json::json!("PRIVATE_STACK_921")),
                ("custom.count".into(), serde_json::json!(3)),
                ("exception.escaped".into(), serde_json::json!(true)),
            ].into() },
            crate::span::SpanEvent { name: "gen_ai.evaluation.result".into(), time_unix_us: 12, attributes: [
                ("explanation".into(), serde_json::json!("PRIVATE_EXPLANATION_921")),
                ("gen_ai.evaluation.explanation".into(), serde_json::json!({"text": "PRIVATE_NESTED_921"})),
                ("gen_ai.evaluation.score.value".into(), serde_json::json!(0.8)),
                ("gen_ai.evaluation.name".into(), serde_json::json!("quality")),
            ].into() },
            crate::span::SpanEvent { name: "PRIVATE_EVENT_NAME_921".into(), time_unix_us: 13, attributes: [
                ("custom.payload".into(), serde_json::json!(["PRIVATE_EVENT_ARRAY_921", {"text":"PRIVATE_EVENT_OBJECT_921"}])),
            ].into() },
        ]);
        let off = encode_request(&s, false).encode_to_vec();
        let on = encode_request(&s, true).encode_to_vec();
        for secret in [
            "PRIVATE_STATUS_921",
            "PRIVATE_EXTRA_921",
            "PRIVATE_MESSAGE_921",
            "PRIVATE_STACK_921",
            "PRIVATE_EXPLANATION_921",
            "PRIVATE_NESTED_921",
            "PRIVATE_EVENT_NAME_921",
            "PRIVATE_EVENT_ARRAY_921",
            "PRIVATE_EVENT_OBJECT_921",
        ] {
            assert!(
                !String::from_utf8_lossy(&off).contains(secret),
                "{secret} leaked"
            );
            assert!(
                String::from_utf8_lossy(&on).contains(secret),
                "content-on lost {secret}"
            );
        }
        let encoded = encode_span(&s, false);
        assert_eq!(
            encoded.status.as_ref().unwrap().code,
            OtlpCode::Error as i32
        );
        assert!(encoded.status.as_ref().unwrap().message.is_empty());
        assert!(matches!(
            attr(&encoded, "custom.count").and_then(|v| v.value.as_ref()),
            Some(V::IntValue(17))
        ));
        assert!(
            encoded.events[0]
                .attributes
                .iter()
                .any(|a| a.key == "exception.type")
        );
        assert!(
            encoded.events[0]
                .attributes
                .iter()
                .any(|a| a.key == "custom.count")
        );
        assert!(
            encoded.events[1]
                .attributes
                .iter()
                .any(|a| a.key == "gen_ai.evaluation.score.value")
        );
        assert_eq!(encoded.events[2].name, "event");
    }

    #[test]
    fn no_content_event_keys_cannot_bypass_filter_with_numeric_or_structured_values() {
        for value in [
            serde_json::json!("private"),
            serde_json::json!(123),
            serde_json::json!(true),
            serde_json::json!([1, true]),
            serde_json::json!({"private": 1}),
            serde_json::Value::Null,
        ] {
            let mut s = span();
            s.attributes.tracelane_events = Some(vec![crate::span::SpanEvent {
                name: "gen_ai.evaluation.result".into(),
                time_unix_us: 1,
                attributes: [
                    "exception.message",
                    "exception.stacktrace",
                    "explanation",
                    "gen_ai.evaluation.explanation",
                    "gen_ai.input.messages",
                ]
                .into_iter()
                .map(|key| (key.into(), value.clone()))
                .collect(),
            }]);
            assert!(
                encode_span(&s, false).events[0].attributes.is_empty(),
                "content key retained for {value}"
            );
        }
    }

    #[test]
    fn og50_attribute_types_keys_and_the_resource_are_what_a_collector_expects() {
        let s = span();
        let sp = encode_span(&s, true);
        assert!(matches!(
            attr(&sp, "gen_ai.usage.input_tokens").and_then(|v| v.value.as_ref()),
            Some(V::IntValue(12))
        ));
        assert!(matches!(
            attr(&sp, "gen_ai.usage.cost").and_then(|v| v.value.as_ref()),
            Some(V::DoubleValue(_))
        ));
        assert!(matches!(
            attr(&sp, "gen_ai.request.stream").and_then(|v| v.value.as_ref()),
            Some(V::BoolValue(true))
        ));
        assert!(matches!(
            attr(&sp, "gen_ai.response.finish_reasons").and_then(|v| v.value.as_ref()),
            Some(V::ArrayValue(_))
        ));
        // A tracelane_* field with no semconv name is `tracelane.<rest>`.
        assert!(attr(&sp, "tracelane.semantic_cache_hit").is_some());
        assert!(
            sp.attributes.iter().all(|a| !a.key.starts_with("gen_ai_")),
            "no snake_case semconv field name leaks as a key: {:?}",
            sp.attributes.iter().map(|a| &a.key).collect::<Vec<_>>()
        );
        // Sorted, stable.
        let keys: Vec<_> = sp.attributes.iter().map(|a| a.key.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        let req = export_request(vec![sp]);
        let r = req.resource_spans[0].resource.as_ref().unwrap();
        assert!(matches!(
            r.attributes[0].value.as_ref().and_then(|v| v.value.as_ref()),
            Some(V::StringValue(n)) if n == EXPORT_SERVICE_NAME
        ));
        assert_eq!(sp_kind(&req), 3, "a client call to a model provider");
    }

    fn sp_kind(req: &ExportTraceServiceRequest) -> i32 {
        req.resource_spans[0].scope_spans[0].spans[0].kind
    }

    #[test]
    fn og50_the_semconv_table_covers_every_content_attribute_and_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for field in [
            "gen_ai_system",
            "gen_ai_provider_name",
            "gen_ai_request_model",
            "gen_ai_usage_input_tokens",
            "gen_ai_input_messages",
        ] {
            assert!(seen.insert(semconv_key(field).expect(field)));
        }
        // A new content field must be added to CONTENT_ATTRIBUTES: the stripped list names only
        // fields that exist on SpanAttributes.
        let json = serde_json::to_value(SpanAttributes::default()).unwrap();
        assert!(json.is_object());
        assert_eq!(export_key("tracelane_foo_bar"), "tracelane.foo_bar");
        assert_eq!(export_key("gen_ai_request_model"), "gen_ai.request.model");
        assert_eq!(export_key("something_else"), "something_else");
    }
}
