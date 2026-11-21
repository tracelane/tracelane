//! Curated OpenInference aliases for recorded gateway spans and OTLP export.
//! These values come from typed fields, never from arbitrary text in `extra`.
use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::SpanAttributes;

const METADATA_KEYS: &[&str] = &[
    "openinference.span.kind",
    "embedding.model_name",
    "llm.model_name",
    "llm.request.model_name",
    "llm.response.model_name",
    "llm.provider",
    "llm.system",
    "llm.token_count.prompt",
    "llm.token_count.completion",
    "llm.token_count.total",
    "llm.token_count.prompt_details.cache_read",
    "llm.token_count.prompt_details.cache_write",
    "llm.token_count.completion_details.reasoning",
    "llm.invocation_parameters",
];

/// A generated metadata alias key (never billed, see the gateway meter).
#[must_use]
pub fn is_generated_metadata(key: &str) -> bool {
    METADATA_KEYS.contains(&key)
}

pub(super) fn owns(key: &str) -> bool {
    METADATA_KEYS.contains(&key)
        || matches!(
            key,
            "input.value" | "output.value" | "input.mime_type" | "output.mime_type"
        )
}

fn known(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty() && *v != "unknown")
}

/// Emit only known operation kinds. Agent identity is not an operation kind.
fn kind(a: &SpanAttributes) -> Option<String> {
    if let Some(kind) = a.openinference_span_kind.as_deref() {
        let kind = kind.to_ascii_uppercase();
        return matches!(
            kind.as_str(),
            "LLM"
                | "EMBEDDING"
                | "CHAIN"
                | "RETRIEVER"
                | "RERANKER"
                | "TOOL"
                | "AGENT"
                | "GUARDRAIL"
                | "EVALUATOR"
                | "PROMPT"
        )
        .then_some(kind);
    }
    match a.gen_ai_operation_name.as_deref()? {
        "chat" | "text_completion" | "generate_content" => Some("LLM".into()),
        "embeddings" | "embedding" => Some("EMBEDDING".into()),
        "execute_tool" => Some("TOOL".into()),
        "invoke_agent" => Some("AGENT".into()),
        "prompt.resolve" => Some("PROMPT".into()),
        _ => None,
    }
}

/// Metadata-only aliases. Missing inputs stay absent, including unknown cache
/// components needed to convert an exclusive prompt count to an inclusive one.
pub(super) fn metadata(a: &SpanAttributes) -> BTreeMap<&'static str, Value> {
    let kind = kind(a);
    let mut out = BTreeMap::new();
    if let Some(kind) = &kind {
        out.insert("openinference.span.kind", json!(kind));
    }
    if kind.as_deref() == Some("EMBEDDING")
        && let Some(model) = known(a.gen_ai_request_model.as_deref())
    {
        out.insert("embedding.model_name", json!(model));
    }
    if kind.as_deref() != Some("LLM") {
        return out;
    }
    let request = known(a.gen_ai_request_model.as_deref());
    let response = known(a.gen_ai_response_model.as_deref());
    let prompt = a
        .gen_ai_usage_input_tokens
        .map(u64::from)
        .and_then(|input| {
            if a.tracelane_usage_input_includes_cache == Some(false) {
                Some(
                    input
                        + u64::from(a.gen_ai_usage_cache_read_input_tokens?)
                        + u64::from(a.gen_ai_usage_cache_creation_input_tokens?),
                )
            } else {
                Some(input)
            }
        });
    let completion = a.gen_ai_usage_output_tokens.map(u64::from);
    let mut parameters = serde_json::Map::new();
    for (name, value) in [
        ("temperature", json!(a.gen_ai_request_temperature)),
        ("top_p", json!(a.gen_ai_request_top_p)),
        ("max_tokens", json!(a.gen_ai_request_max_tokens)),
        ("seed", json!(a.gen_ai_request_seed)),
    ] {
        if value.is_number() {
            parameters.insert(name.into(), value);
        }
    }
    for (key, value) in [
        ("llm.model_name", json!(response.or(request))),
        ("llm.request.model_name", json!(request)),
        ("llm.response.model_name", json!(response)),
        (
            "llm.provider",
            json!(known(a.gen_ai_provider_name.as_deref())),
        ),
        ("llm.system", json!(known(a.gen_ai_system.as_deref()))),
        ("llm.token_count.prompt", json!(prompt)),
        ("llm.token_count.completion", json!(completion)),
        (
            "llm.token_count.total",
            json!(prompt.zip(completion).map(|(i, o)| i + o)),
        ),
        (
            "llm.token_count.prompt_details.cache_read",
            json!(a.gen_ai_usage_cache_read_input_tokens),
        ),
        (
            "llm.token_count.prompt_details.cache_write",
            json!(a.gen_ai_usage_cache_creation_input_tokens),
        ),
        (
            "llm.token_count.completion_details.reasoning",
            json!(a.gen_ai_usage_reasoning_output_tokens),
        ),
    ] {
        if !value.is_null() {
            out.insert(key, value);
        }
    }
    if !parameters.is_empty() {
        out.insert(
            "llm.invocation_parameters",
            Value::String(Value::Object(parameters).to_string()),
        );
    }
    out
}

/// Refresh generated aliases after operation-specific overrides, before metering
/// and publication. Repeating this operation adds no extra alias bytes.
pub fn enrich(a: &mut SpanAttributes) {
    // A final byte stamp seals the chosen wire shape, including omitted aliases.
    if a.extra.contains_key("tracelane_span_bytes") {
        return;
    }
    let aliases = metadata(a);
    remove_metadata_aliases(a);
    a.extra.extend(
        aliases
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value)),
    );
}

/// Remove generated metadata when it cannot fit alongside the original record.
pub fn remove_metadata_aliases(a: &mut SpanAttributes) {
    a.extra
        .retain(|key, _| !METADATA_KEYS.contains(&key.as_str()));
}

/// Content aliases are derived at EXPORT from already-gated, redacted and capped typed values;
/// the gateway never stores a second copy (it would double stored and billed bytes). An
/// ingested SDK span that carried its own `input.value` keeps it. This function is called
/// only when the destination opted into content. Untrusted MIME strings are limited to
/// supported literal types and JSON must actually parse.
pub(super) fn content(a: &SpanAttributes) -> BTreeMap<&'static str, Value> {
    let tool = a.gen_ai_operation_name.as_deref() == Some("execute_tool");
    let derived = |messages: Option<&Value>, tool_text: Option<&String>| -> Option<String> {
        if tool {
            tool_text.cloned()
        } else {
            messages.and_then(|m| serde_json::to_string(m).ok())
        }
    };
    let mut out = BTreeMap::new();
    for (value_key, mime_key, stored, fallback) in [
        (
            "input.value",
            "input.mime_type",
            a.input_value.clone(),
            derived(
                a.gen_ai_input_messages.as_ref(),
                a.gen_ai_tool_call_arguments.as_ref(),
            ),
        ),
        (
            "output.value",
            "output.mime_type",
            a.output_value.clone(),
            derived(
                a.gen_ai_output_messages.as_ref(),
                a.gen_ai_tool_call_result.as_ref(),
            ),
        ),
    ] {
        if let Some(value) = stored {
            out.insert(value_key, json!(value));
            let mime = a.extra.get(mime_key).and_then(Value::as_str);
            if mime == Some("text/plain")
                || (mime == Some("application/json")
                    && serde_json::from_str::<Value>(&value).is_ok())
            {
                out.insert(mime_key, json!(mime));
            }
        } else if let Some(value) = fallback {
            let mime = if serde_json::from_str::<Value>(&value).is_ok() {
                "application/json"
            } else {
                "text/plain"
            };
            out.insert(value_key, json!(value));
            out.insert(mime_key, json!(mime));
        }
    }
    out
}
