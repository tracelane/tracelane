//! OpenInference aliases are filled after canonical attributes, independent of wire order.
use super::content::{OtlpCapturePolicy, note_drop};
use super::decode::{
    any_value_f32, any_value_f64, any_value_json, any_value_string, any_value_u32, any_value_u64,
};
use crate::span::{RetrievalDocument, SpanAttributes};
use opentelemetry_proto::tonic::common::v1::KeyValue;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn is_token_count(key: &str) -> bool {
    matches!(
        key,
        "llm.token_count.prompt"
            | "llm.token_count.completion"
            | "llm.token_count.prompt_details.cache_read"
            | "llm.token_count.prompt_details.cache_write"
            | "llm.token_count.completion_details.reasoning"
    )
}

pub(super) fn handles(key: &str) -> bool {
    matches!(
        key,
        "openinference.span.kind"
            | "llm.model_name"
            | "llm.request.model_name"
            | "llm.response.model_name"
            | "llm.provider"
            | "llm.system"
            | "llm.cost.total"
            | "input.value"
            | "output.value"
            | "input.mime_type"
            | "output.mime_type"
            | "tool.description"
            | "tool.id"
            | "tool_call.id"
            | "tool.parameters"
            | "tool_call.function.arguments"
            | "llm.invocation_parameters"
            | "llm.tools"
    ) || is_token_count(key)
        || [
            "llm.input_messages.",
            "llm.output_messages.",
            "llm.tools.",
            "retrieval.documents.",
        ]
        .iter()
        .any(|p| key.starts_with(p))
}

pub(super) fn apply(attrs: &[KeyValue], out: &mut SpanAttributes, caps: &OtlpCapturePolicy) {
    let mut input = BTreeMap::new();
    let mut output = BTreeMap::new();
    let mut documents = BTreeMap::<usize, RetrievalDocument>::new();
    let mut tools = BTreeMap::<usize, Value>::new();
    for kv in attrs {
        let Some(av) = &kv.value else { continue };
        let key = kv.key.as_str();
        match key {
            "openinference.span.kind" => {
                out.openinference_span_kind = any_value_string(av)
                    .map(|s| s.to_ascii_lowercase())
                    .filter(|s| {
                        matches!(
                            s.as_str(),
                            "llm"
                                | "chain"
                                | "tool"
                                | "retriever"
                                | "reranker"
                                | "embedding"
                                | "agent"
                                | "guardrail"
                                | "evaluator"
                                | "prompt"
                        )
                    })
            }
            "llm.model_name" | "llm.request.model_name" => {
                out.gen_ai_request_model = out
                    .gen_ai_request_model
                    .take()
                    .or_else(|| any_value_string(av));
            }
            "llm.response.model_name" => {
                out.gen_ai_response_model = out
                    .gen_ai_response_model
                    .take()
                    .or_else(|| any_value_string(av));
            }
            "llm.provider" => {
                out.gen_ai_provider_name = out
                    .gen_ai_provider_name
                    .take()
                    .or_else(|| any_value_string(av));
            }
            "llm.system" => {
                out.gen_ai_system = out.gen_ai_system.take().or_else(|| any_value_string(av));
            }
            "llm.token_count.prompt" => {
                out.gen_ai_usage_input_tokens =
                    out.gen_ai_usage_input_tokens.or_else(|| any_value_u32(av));
            }
            "llm.token_count.completion" => {
                out.gen_ai_usage_output_tokens =
                    out.gen_ai_usage_output_tokens.or_else(|| any_value_u32(av));
            }
            "llm.token_count.prompt_details.cache_read" => {
                out.gen_ai_usage_cache_read_input_tokens = out
                    .gen_ai_usage_cache_read_input_tokens
                    .or_else(|| any_value_u32(av));
            }
            "llm.token_count.prompt_details.cache_write" => {
                out.gen_ai_usage_cache_creation_input_tokens = out
                    .gen_ai_usage_cache_creation_input_tokens
                    .or_else(|| any_value_u32(av));
            }
            "llm.token_count.completion_details.reasoning" => {
                out.gen_ai_usage_reasoning_output_tokens = out
                    .gen_ai_usage_reasoning_output_tokens
                    .or_else(|| any_value_u32(av));
            }
            "llm.cost.total" => {
                out.gen_ai_usage_cost = out.gen_ai_usage_cost.or_else(|| any_value_f64(av));
            }
            "input.value" => out.input_value = any_value_string(av),
            "output.value" => out.output_value = any_value_string(av),
            "input.mime_type" | "output.mime_type" => {
                metadata(out, key, scalar(av), caps);
            }
            // Through `metadata()` so the 256-byte cap applies, exactly like the
            // standard `gen_ai.tool.description` (security review 2026-09-29).
            "tool.description" => {
                if !out.extra.contains_key("gen_ai.tool.description") {
                    metadata(
                        out,
                        "gen_ai.tool.description",
                        any_value_string(av).map(Value::String),
                        caps,
                    );
                }
            }
            "tool.id" | "tool_call.id" => {
                out.gen_ai_tool_call_id = out
                    .gen_ai_tool_call_id
                    .take()
                    .or_else(|| any_value_string(av));
            }
            "tool.parameters" | "tool_call.function.arguments" => {
                out.gen_ai_tool_call_arguments = out
                    .gen_ai_tool_call_arguments
                    .take()
                    .or_else(|| any_value_string(av));
            }
            "llm.invocation_parameters" => {
                if let Some(Value::Object(config)) = any_value_json(av) {
                    // Conversion through the wire helpers shares the canonical numeric validation.
                    for (key, target) in [
                        ("temperature", "gen_ai.request.temperature"),
                        ("top_p", "gen_ai.request.top_p"),
                        ("max_tokens", "gen_ai.request.max_tokens"),
                        ("seed", "gen_ai.request.seed"),
                    ] {
                        let Some(value) = config.get(key) else {
                            continue;
                        };
                        let value = opentelemetry_proto::tonic::common::v1::AnyValue { value: value.as_i64().map(opentelemetry_proto::tonic::common::v1::any_value::Value::IntValue).or_else(|| value.as_f64().map(opentelemetry_proto::tonic::common::v1::any_value::Value::DoubleValue)) };
                        match target {
                            "gen_ai.request.temperature" => {
                                out.gen_ai_request_temperature = out
                                    .gen_ai_request_temperature
                                    .or_else(|| any_value_f32(&value))
                            }
                            "gen_ai.request.top_p" => {
                                out.gen_ai_request_top_p =
                                    out.gen_ai_request_top_p.or_else(|| any_value_f32(&value))
                            }
                            "gen_ai.request.max_tokens" => {
                                out.gen_ai_request_max_tokens = out
                                    .gen_ai_request_max_tokens
                                    .or_else(|| any_value_u32(&value))
                            }
                            _ => {
                                out.gen_ai_request_seed =
                                    out.gen_ai_request_seed.or_else(|| any_value_u64(&value))
                            }
                        }
                    }
                }
                // The raw parameter string is NOT kept: instrumentors put `user`,
                // `instructions` or `prediction` text in it. Only the four extracted
                // numbers above survive (security review 2026-09-29).
            }
            "llm.tools" => {
                if let Some(Value::Array(values)) = any_value_json(av) {
                    for (i, v) in values.into_iter().enumerate() {
                        tools.insert(i, v);
                    }
                }
            }
            _ => {
                if let Some((i, field)) = indexed(key, "llm.input_messages.", ".message.") {
                    message(&mut input, i, field, any_value_string(av));
                } else if let Some((i, field)) = indexed(key, "llm.output_messages.", ".message.") {
                    message(&mut output, i, field, any_value_string(av));
                } else if let Some((i, field)) = indexed(key, "retrieval.documents.", ".document.")
                {
                    match field {
                        "id" => documents.entry(i).or_default().id = any_value_string(av),
                        "score" => {
                            documents.entry(i).or_default().score =
                                any_value_f64(av).filter(|v| v.is_finite())
                        }
                        "content" => documents.entry(i).or_default().content = any_value_string(av),
                        _ => {}
                    }
                } else if let Some((i, field)) = indexed(key, "llm.tools.", ".tool.") {
                    match field {
                        "name" => {
                            if let Some(v) = any_value_string(av) {
                                tools.entry(i).or_insert(json!({}))["name"] = json!(v);
                            }
                        }
                        "json_schema" => {
                            if let Some(v) = any_value_json(av) {
                                let tool = tools.entry(i).or_insert(json!({}));
                                if tool.get("name").is_none() {
                                    *tool = v;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        // Retain only the explicitly classified non-content scalar aliases here.
        if matches!(
            key,
            "llm.model_name"
                | "llm.request.model_name"
                | "llm.response.model_name"
                | "llm.provider"
                | "llm.system"
                | "llm.cost.total"
        ) || is_token_count(key)
        {
            metadata(out, key, scalar(av), caps);
        }
    }
    if out.gen_ai_input_messages.is_none() && !input.is_empty() {
        out.gen_ai_input_messages = Some(messages(input));
    }
    if out.gen_ai_output_messages.is_none() && !output.is_empty() {
        out.gen_ai_output_messages = Some(messages(output));
    }
    if let Some(Value::Array(messages)) = &out.gen_ai_output_messages {
        let names: Vec<String> = messages
            .iter()
            .filter_map(|m| m.get("tool_calls").and_then(Value::as_array))
            .flatten()
            .filter_map(|t| t.pointer("/function/name").and_then(Value::as_str))
            .map(str::to_owned)
            .take(caps.passthrough_max_array_items)
            .collect();
        if out.tracelane_response_tool_names.is_none() && !names.is_empty() {
            out.tracelane_response_tool_names = Some(names);
        }
    }
    if !tools.is_empty() {
        record_tools(out, tools.into_values(), caps);
    }
    if out.tracelane_retrieval_documents.is_none() && !documents.is_empty() {
        note_drop(
            out,
            "cap",
            documents.len().saturating_sub(caps.max_retrieval_documents),
        );
        out.tracelane_retrieval_documents = Some(
            documents
                .into_values()
                .take(caps.max_retrieval_documents)
                .collect(),
        );
    }
}

pub(super) fn metadata(
    out: &mut SpanAttributes,
    key: &str,
    value: Option<Value>,
    caps: &OtlpCapturePolicy,
) {
    if let Some(value) = value.filter(|v| {
        v.is_number()
            || v.is_boolean()
            || v.as_str()
                .is_some_and(|s| s.len() <= caps.passthrough_max_string_bytes)
    }) {
        out.extra.entry(key.into()).or_insert(value);
    }
}

pub(super) fn record_tools(
    out: &mut SpanAttributes,
    tools: impl Iterator<Item = Value>,
    caps: &OtlpCapturePolicy,
) {
    let tools: Vec<Value> = tools.collect();
    let names = tools
        .iter()
        .filter_map(|t| {
            t.pointer("/function/name")
                .or_else(|| t.get("name"))
                .or_else(|| t.get("tool.name"))
        })
        .filter_map(Value::as_str)
        .filter(|s| s.len() <= caps.passthrough_max_string_bytes)
        .take(caps.passthrough_max_array_items)
        .map(str::to_owned)
        .collect();
    if out.tracelane_request_tool_count.is_none() {
        out.tracelane_request_tool_count = u32::try_from(tools.len()).ok();
    }
    if out.tracelane_request_tool_names.is_none() {
        out.tracelane_request_tool_names = Some(names);
    }
}

fn indexed<'a>(key: &'a str, prefix: &str, middle: &str) -> Option<(usize, &'a str)> {
    let (index, field) = key.strip_prefix(prefix)?.split_once(middle)?;
    Some((index.parse().ok()?, field))
}

#[derive(Default)]
struct Message {
    values: serde_json::Map<String, Value>,
    calls: BTreeMap<usize, serde_json::Map<String, Value>>,
}
fn message(messages: &mut BTreeMap<usize, Message>, i: usize, field: &str, value: Option<String>) {
    let Some(value) = value else { return };
    if matches!(field, "role" | "content" | "name" | "tool_call_id") {
        messages
            .entry(i)
            .or_default()
            .values
            .insert(field.into(), json!(value));
    } else if let Some((j, field)) = indexed(field, "tool_calls.", ".tool_call.function.")
        && matches!(field, "name" | "arguments")
    {
        messages
            .entry(i)
            .or_default()
            .calls
            .entry(j)
            .or_default()
            .insert(field.into(), json!(value));
    }
}
fn messages(messages: BTreeMap<usize, Message>) -> Value {
    Value::Array(
        messages
            .into_values()
            .map(|mut m| {
                if !m.calls.is_empty() {
                    m.values.insert(
                        "tool_calls".into(),
                        Value::Array(
                            m.calls
                                .into_values()
                                .map(|f| json!({"type":"function", "function":f}))
                                .collect(),
                        ),
                    );
                }
                Value::Object(m.values)
            })
            .collect(),
    )
}

pub(super) fn scalar(av: &opentelemetry_proto::tonic::common::v1::AnyValue) -> Option<Value> {
    use opentelemetry_proto::tonic::common::v1::any_value::Value as Wire;
    match av.value.as_ref()? {
        Wire::StringValue(s) => Some(Value::String(s.clone())),
        Wire::IntValue(v) => Some(json!(v)),
        Wire::DoubleValue(v) if v.is_finite() => Some(json!(v)),
        Wire::BoolValue(v) => Some(json!(v)),
        _ => None,
    }
}
