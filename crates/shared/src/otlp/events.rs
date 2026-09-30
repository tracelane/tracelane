//! Retain bounded event metadata and fold message events through the content gate.
use super::content::{OtlpCapturePolicy, note_drop, truncate_utf8};
use super::decode::{
    any_value_json, any_value_string, otlp_span_id_to_uuid, otlp_trace_id_to_uuid,
};
use crate::span::{SpanAttributes, SpanEvent, SpanLink};
use opentelemetry_proto::tonic::trace::v1::Span;
use serde_json::{Value, json};

pub(super) fn apply(span: &Span, out: &mut SpanAttributes, caps: &OtlpCapturePolicy) {
    let mut events = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut systems = Vec::new();
    note_drop(
        out,
        "cap",
        span.events.len().saturating_sub(caps.max_events_per_span),
    );
    for event in span.events.iter().take(caps.max_events_per_span) {
        let get = |key: &str| {
            event
                .attributes
                .iter()
                .find(|a| a.key == key)
                .and_then(|a| a.value.as_ref())
                .and_then(any_value_json)
        };
        let role = match event.name.as_str() {
            "gen_ai.user.message" => Some("user"),
            "gen_ai.system.message" => Some("system"),
            "gen_ai.assistant.message" => Some("assistant"),
            "gen_ai.tool.message" => Some("tool"),
            "gen_ai.choice" => Some("assistant"),
            _ => None,
        };
        if let Some(role) = role {
            let mut message = get("message").or_else(|| get("body"));
            if let Some(body) = message.as_mut()
                && let Some(inner) = body.get("message")
            {
                *body = inner.clone();
            }
            if let Some(Value::String(text)) = message.as_ref() {
                message = Some(json!({"content":text}));
            }
            if message.is_none() {
                message = get("content").map(|v| json!({"content":v}));
            }
            if let Some(Value::Object(mut message)) = message {
                message.entry("role").or_insert(json!(role));
                let message = Value::Object(message);
                match role {
                    "assistant" => outputs.push(message),
                    "system" => systems.push(message),
                    _ => inputs.push(message),
                }
            }
            continue;
        }
        if event.name == "gen_ai.client.inference.operation.details" {
            let body = get("body").unwrap_or(Value::Null);
            for (key, target) in [
                ("gen_ai.input.messages", &mut inputs),
                ("gen_ai.output.messages", &mut outputs),
                ("gen_ai.system_instructions", &mut systems),
            ] {
                if let Some(value) = get(key).or_else(|| body.get(key).cloned()) {
                    match value {
                        Value::Array(values) => target.extend(values),
                        v => target.push(v),
                    }
                }
            }
            continue;
        }
        let mut name = event.name.clone();
        // An event name is producer text: bounded by the same per-event cap as its
        // attributes, on a char boundary (security review 2026-09-29).
        if name.len() > caps.max_event_attribute_bytes {
            let mut cut = caps.max_event_attribute_bytes;
            while !name.is_char_boundary(cut) {
                cut -= 1;
            }
            name.truncate(cut);
        }
        let mut kept = SpanEvent {
            name,
            time_unix_us: event.time_unix_nano / 1000,
            attributes: Default::default(),
        };
        for attr in &event.attributes {
            let Some(av) = &attr.value else { continue };
            let key = attr.key.as_str();
            let known = match event.name.as_str() {
                "exception" => matches!(
                    key,
                    "exception.type" | "exception.message" | "exception.stacktrace"
                ),
                "gen_ai.evaluation.result" => matches!(
                    key,
                    "gen_ai.evaluation.name"
                        | "score.value"
                        | "score.label"
                        | "gen_ai.evaluation.score.value"
                        | "gen_ai.evaluation.score.label"
                        | "explanation"
                        | "gen_ai.evaluation.explanation"
                ),
                _ => false,
            };
            if known {
                let cap = if key == "exception.stacktrace" {
                    caps.max_stacktrace_bytes
                } else {
                    caps.max_event_attribute_bytes
                };
                let value = if let Some(mut text) = any_value_string(av) {
                    truncate_utf8(&mut text, cap);
                    Some(Value::String(text))
                } else {
                    super::openinference::scalar(av)
                };
                if let Some(value) = value {
                    if event.name == "exception" {
                        if key == "exception.type" && out.exception_type.is_none() {
                            out.exception_type = value.as_str().map(str::to_owned);
                        }
                        if key == "exception.message" && out.exception_message.is_none() {
                            out.exception_message = value.as_str().map(str::to_owned);
                        }
                    }
                    kept.attributes.insert(key.into(), value);
                }
            } else {
                super::passthrough::collect(out, key, av, caps, Some(events.len()));
            }
        }
        events.push(kept);
    }
    if out.gen_ai_input_messages.is_none() && !inputs.is_empty() {
        out.gen_ai_input_messages = Some(Value::Array(inputs));
    }
    if out.gen_ai_output_messages.is_none() && !outputs.is_empty() {
        out.gen_ai_output_messages = Some(Value::Array(outputs));
    }
    if out.gen_ai_system_instructions.is_none() && !systems.is_empty() {
        out.gen_ai_system_instructions = Some(Value::Array(systems));
    }
    out.tracelane_events = (!events.is_empty()).then_some(events);
    note_drop(
        out,
        "cap",
        span.links.len().saturating_sub(caps.max_links_per_span),
    );
    let mut links = Vec::new();
    for link in span.links.iter().take(caps.max_links_per_span) {
        note_drop(out, "link_attrs", link.attributes.len());
        match (
            otlp_trace_id_to_uuid(&link.trace_id),
            otlp_span_id_to_uuid(&link.span_id),
        ) {
            (Ok(trace_id), Ok(span_id)) => links.push(SpanLink { trace_id, span_id }),
            _ => note_drop(out, "invalid_link", 1),
        }
    }
    out.tracelane_links = (!links.is_empty()).then_some(links);
}
