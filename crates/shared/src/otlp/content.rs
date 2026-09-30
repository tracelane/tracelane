//! Content decisions at the authenticated OTLP publish/store boundaries.

use crate::TracelaneSpan;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureHalves {
    pub input: bool,
    pub output: bool,
    pub max_field_bytes: usize,
}

impl CaptureHalves {
    /// Unknown policy fails CLOSED for content, independently of sampling.
    pub fn closed() -> Self {
        Self::default()
    }
}

/// Bounded decoder policy, loaded through each process's existing cache.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct OtlpCapturePolicy {
    pub passthrough_max_keys_per_span: usize,
    pub passthrough_max_key_bytes: usize,
    pub passthrough_max_string_bytes: usize,
    pub passthrough_max_array_items: usize,
    pub max_events_per_span: usize,
    pub max_event_attribute_bytes: usize,
    pub max_stacktrace_bytes: usize,
    pub max_links_per_span: usize,
    pub max_retrieval_documents: usize,
    pub default_max_field_bytes: usize,
}

impl OtlpCapturePolicy {
    /// No control plane uses the reviewed seed. Invalid embedded data fails
    /// CLOSED to zero budgets; the seed test refuses that build.
    pub fn embedded() -> Self {
        static POLICY: std::sync::LazyLock<OtlpCapturePolicy> = std::sync::LazyLock::new(|| {
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../../apps/web/db/plans.v3.json"
            ))
            .ok()
            .and_then(|v| serde_json::from_value(v["policy"]["otlp_capture"].clone()).ok())
            .unwrap_or_default()
        });
        POLICY.clone()
    }
}

/// Remove disabled halves and bound each retained field before publication.
pub fn apply_capture(span: &mut TracelaneSpan, halves: &CaptureHalves) {
    let a = &mut span.attributes;
    let mut withheld = Vec::new();
    let mut input = gate_json(
        &mut a.gen_ai_input_messages,
        halves.input,
        halves.max_field_bytes,
    ) | gate_json(
        &mut a.gen_ai_system_instructions,
        halves.input,
        halves.max_field_bytes,
    );
    let mut output = gate_json(
        &mut a.gen_ai_output_messages,
        halves.output,
        halves.max_field_bytes,
    );
    input |= gate_string(&mut a.input_value, halves.input, halves.max_field_bytes);
    input |= gate_string(
        &mut a.gen_ai_tool_call_result,
        halves.input,
        halves.max_field_bytes,
    );
    input |= gate_string(
        &mut a.tracelane_retrieval_query,
        halves.input,
        halves.max_field_bytes,
    );
    output |= gate_string(&mut a.output_value, halves.output, halves.max_field_bytes);
    output |= gate_string(
        &mut a.gen_ai_tool_call_arguments,
        halves.output,
        halves.max_field_bytes,
    );
    if let Some(documents) = &mut a.tracelane_retrieval_documents {
        for document in documents {
            input |= gate_string(&mut document.content, halves.input, halves.max_field_bytes);
        }
    }
    if let Some(events) = &mut a.tracelane_events {
        for event in events {
            // A producer-chosen event NAME can carry text (`add_event(f"user asked: {q}")`).
            // Unless capture is fully on, only the well-known names survive; any other
            // name is replaced (security review 2026-09-29).
            let known_name = event.name == "exception" || event.name.starts_with("gen_ai.");
            if !(known_name || (halves.input && halves.output)) {
                event.name = "event".into();
                input = true;
            }
            if event.name == "gen_ai.evaluation.result" {
                for key in ["explanation", "gen_ai.evaluation.explanation"] {
                    if !halves.output {
                        output |= event.attributes.remove(key).is_some();
                    } else if let Some(serde_json::Value::String(text)) =
                        event.attributes.get_mut(key)
                    {
                        truncate_utf8(text, halves.max_field_bytes);
                    }
                }
            }
        }
    }
    super::passthrough::apply(a, halves);
    if input {
        withheld.push("input".into());
    }
    if output {
        withheld.push("output".into());
    }
    a.tracelane_content_withheld = (!withheld.is_empty()).then_some(withheld);
}

pub(crate) fn note_drop(attrs: &mut crate::SpanAttributes, reason: &str, count: usize) {
    if count == 0 {
        return;
    }
    let dropped = attrs
        .tracelane_attrs_dropped
        .get_or_insert_with(Default::default);
    dropped.count += count;
    *dropped.reasons.entry(reason.into()).or_default() += count;
}

pub(super) fn gate_string(field: &mut Option<String>, enabled: bool, cap: usize) -> bool {
    if !enabled {
        return field.take().is_some();
    }
    if let Some(text) = field {
        truncate_utf8(text, cap);
    }
    false
}

fn gate_json(field: &mut Option<serde_json::Value>, enabled: bool, cap: usize) -> bool {
    if !enabled {
        return field.take().is_some();
    }
    if let Some(value) = field {
        let mut text = match value {
            serde_json::Value::String(s) => s.clone(),
            _ => value.to_string(),
        };
        if text.len() > cap {
            truncate_utf8(&mut text, cap);
            *value = serde_json::Value::String(text);
        }
    }
    false
}

/// The cap includes the marker. Tiny caps still never exceed the bound.
pub fn truncate_utf8(text: &mut String, cap: usize) {
    const MARK: &str = "…[truncated]";
    if text.len() <= cap {
        return;
    }
    let mut end = if cap > MARK.len() {
        cap - MARK.len()
    } else {
        cap
    };
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    if cap > MARK.len() {
        text.push_str(MARK);
    }
}

/// Content families may exceed the attribute cap: the byte-bounded batch still
/// reaches the typed content gate, where disabled fields are dropped and enabled
/// fields are capped. Unmapped members of these families are never stored raw.
pub fn is_content_key(key: &str) -> bool {
    matches!(
        key,
        "input.value" | "output.value" | "gen_ai.system_instructions"
    ) || key.split('.').any(|part| {
        part.starts_with("prompt")
            || part.starts_with("completion")
            || part.starts_with("messages")
            || matches!(
                part,
                "content"
                    | "prompt"
                    | "completion"
                    | "messages"
                    | "input_messages"
                    | "output_messages"
                    | "input"
                    | "output"
                    | "arguments"
                    | "result"
            )
    }) || key.ends_with(".query.text")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpanAttributes, SpanStatus, TenantId};
    use serde_json::json;

    #[test]
    fn otlp_capture_seed_contains_every_reviewed_cap() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        for key in [
            "passthrough_max_keys_per_span",
            "passthrough_max_key_bytes",
            "passthrough_max_string_bytes",
            "passthrough_max_array_items",
            "max_events_per_span",
            "max_event_attribute_bytes",
            "max_stacktrace_bytes",
            "max_links_per_span",
            "max_retrieval_documents",
            "default_max_field_bytes",
        ] {
            assert!(
                seed["policy"]["otlp_capture"][key]
                    .as_u64()
                    .is_some_and(|n| n > 0),
                "missing positive policy.otlp_capture.{key}"
            );
        }
    }

    fn span() -> TracelaneSpan {
        TracelaneSpan {
            span_id: uuid::Uuid::nil(),
            trace_id: uuid::Uuid::nil(),
            parent_span_id: None,
            tenant_id: TenantId::from_jwt_claim(uuid::Uuid::nil()),
            name: "test".into(),
            start_time: chrono::DateTime::UNIX_EPOCH,
            end_time: None,
            attributes: SpanAttributes::default(),
            status: SpanStatus::default(),
        }
    }

    #[test]
    fn capture_off_strips_arrived_content_and_marks_only_arrived_halves() {
        let mut s = span();
        s.attributes.gen_ai_input_messages = Some(json!([{"content": "private"}]));
        s.attributes.gen_ai_system_instructions = Some(json!("secret"));
        s.attributes.gen_ai_usage_input_tokens = Some(7);
        apply_capture(&mut s, &CaptureHalves::closed());
        assert_eq!(s.attributes.gen_ai_input_messages, None);
        assert_eq!(s.attributes.gen_ai_system_instructions, None);
        assert_eq!(s.attributes.gen_ai_usage_input_tokens, Some(7));
        assert_eq!(
            serde_json::to_value(&s.attributes).unwrap()["tracelane_content_withheld"],
            json!(["input"])
        );
        let mut empty = span();
        apply_capture(&mut empty, &CaptureHalves::closed());
        assert!(
            serde_json::to_value(&empty.attributes)
                .unwrap()
                .get("tracelane_content_withheld")
                .is_none()
        );
    }

    #[test]
    fn capture_halves_are_independent_and_kept_json_is_utf8_capped() {
        let mut s = span();
        s.attributes.gen_ai_input_messages = Some(json!([{"content": "é".repeat(80)}]));
        s.attributes.gen_ai_output_messages = Some(json!("private output"));
        apply_capture(
            &mut s,
            &CaptureHalves {
                input: true,
                output: false,
                max_field_bytes: 40,
            },
        );
        assert_eq!(s.attributes.gen_ai_output_messages, None);
        let kept = s.attributes.gen_ai_input_messages.unwrap();
        let text = kept.as_str().expect("oversized JSON becomes marked text");
        assert!(text.len() <= 40);
        assert!(text.ends_with("…[truncated]"));
    }
}
