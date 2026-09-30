//! Transport aliases feed the same label normalizer as gateway headers.
use super::decode::any_value_string;
use crate::{
    SpanAttributes,
    labels::{LabelCaps, RawLabels, bound_labels},
};
use opentelemetry_proto::tonic::common::v1::{KeyValue, any_value::Value as Wire};

pub(super) fn handles(key: &str) -> bool {
    matches!(
        key,
        "metadata" | "tracelane.tags" | "tag.tags" | "langfuse.trace.tags"
    ) || key.starts_with("tracelane.metadata.")
        || key.starts_with("langfuse.trace.metadata.")
}
pub(super) fn apply(attrs: &[KeyValue], out: &mut SpanAttributes, caps: &LabelCaps) {
    let mut raw = RawLabels {
        environment: out.deployment_environment.take(),
        release: out.service_version.take(),
        service: out.service_name.take(),
        ..Default::default()
    };
    // Canonical entries precede aliases; first occurrence wins in the shared bounder.
    for prefix in ["tracelane.metadata.", "langfuse.trace.metadata."] {
        for attr in attrs {
            if let Some(key) = attr.key.strip_prefix(prefix) {
                let value = attr
                    .value
                    .as_ref()
                    .and_then(super::openinference::scalar)
                    .unwrap_or(serde_json::Value::Null);
                raw.metadata.push((key.into(), value));
            }
        }
    }
    if let Some(attr) = attrs.iter().find(|a| a.key == "metadata") {
        raw.metadata_json = attr.value.as_ref().and_then(any_value_string);
        if raw.metadata_json.is_none() {
            raw.metadata.push((String::new(), serde_json::Value::Null));
        }
    }
    let mut invalid_tags = 0;
    if let Some(attr) = ["tracelane.tags", "tag.tags", "langfuse.trace.tags"]
        .iter()
        .find_map(|key| attrs.iter().find(|a| a.key == *key))
    {
        match attr.value.as_ref().and_then(|a| a.value.as_ref()) {
            Some(Wire::StringValue(s)) => raw.tags.push(s.clone()),
            Some(Wire::ArrayValue(array)) => {
                for value in &array.values {
                    if let Some(s) = any_value_string(value) {
                        raw.tags.push(s);
                    } else {
                        invalid_tags += 1;
                    }
                }
            }
            _ => invalid_tags += 1,
        }
    }
    let (labels, mut dropped) = bound_labels(raw, caps);
    if invalid_tags > 0 {
        *dropped.entry("tags".into()).or_default() += invalid_tags;
    }
    labels.write_to(out, &dropped);
}
