//! Candidate attributes stay process-local until the workspace content gate runs.
use super::content::{CaptureHalves, OtlpCapturePolicy, is_content_key, note_drop};
use super::openinference::scalar;
use crate::SpanAttributes;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value::Value as Wire};
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct PendingAttributes {
    pub(crate) items: Vec<(String, Value, Option<usize>)>,
    pub(crate) limit: usize,
}

pub(super) fn collect(
    out: &mut SpanAttributes,
    key: &str,
    av: &AnyValue,
    caps: &OtlpCapturePolicy,
    event: Option<usize>,
) {
    if is_content_key(key) {
        note_drop(out, "content_unmapped", 1);
        return;
    }
    if !key.contains('.')
        || key.starts_with("tracelane.")
        || key.starts_with("tracelane_")
        || key.len() > caps.passthrough_max_key_bytes
    {
        note_drop(out, "cap", 1);
        return;
    }
    let value = match av.value.as_ref() {
        Some(Wire::ArrayValue(a)) => {
            if a.values.len() > caps.passthrough_max_array_items {
                note_drop(out, "cap", 1);
            }
            let mut values = Vec::new();
            for av in a.values.iter().take(caps.passthrough_max_array_items) {
                if let Some(v) = scalar(av).filter(|v| {
                    v.as_str()
                        .is_none_or(|s| s.len() <= caps.passthrough_max_string_bytes)
                }) {
                    values.push(v);
                } else {
                    note_drop(out, "cap", 1);
                }
            }
            Some(Value::Array(values))
        }
        _ => scalar(av).filter(|v| {
            v.as_str()
                .is_none_or(|s| s.len() <= caps.passthrough_max_string_bytes)
        }),
    };
    if let Some(value) = value {
        if event.is_some() && value.to_string().len() > caps.max_event_attribute_bytes {
            note_drop(out, "cap", 1);
            return;
        }
        out.otlp_pending.limit = caps.passthrough_max_keys_per_span;
        out.otlp_pending.items.push((key.into(), value, event));
    } else {
        note_drop(out, "cap", 1);
    }
}

pub(super) fn apply(out: &mut SpanAttributes, halves: &CaptureHalves) {
    let pending = std::mem::take(&mut out.otlp_pending);
    let mut kept = 0;
    for (key, mut value, event) in pending.items {
        if !(halves.input && halves.output) {
            if value.is_string() {
                note_drop(out, "string_capture_off", 1);
                continue;
            }
            if let Value::Array(values) = &mut value {
                let before = values.len();
                values.retain(|v| !v.is_string());
                note_drop(out, "string_capture_off", before - values.len());
                if before > 0 && values.is_empty() {
                    continue;
                }
            }
        }
        if kept >= pending.limit {
            note_drop(out, "cap", 1);
            continue;
        }
        let inserted = match event {
            Some(i) => {
                if let Some(event) = out
                    .tracelane_events
                    .as_mut()
                    .and_then(|events| events.get_mut(i))
                {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        event.attributes.entry(key)
                    {
                        entry.insert(value);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            None => {
                if let std::collections::hash_map::Entry::Vacant(entry) = out.extra.entry(key) {
                    entry.insert(value);
                    true
                } else {
                    false
                }
            }
        };
        if inserted {
            kept += 1;
        } else {
            note_drop(out, "cap", 1);
        }
    }
}
