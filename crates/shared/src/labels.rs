//! Bounded developer-supplied labels shared by proxy headers and OTLP.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct LabelCaps {
    pub max_metadata_keys: usize,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub max_metadata_total_bytes: usize,
    pub max_tags: usize,
    pub max_tag_bytes: usize,
    pub max_environment_bytes: usize,
    pub max_release_bytes: usize,
    pub max_service_bytes: usize,
}
impl LabelCaps {
    pub fn embedded() -> Self {
        embedded("request_labels")
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct OutputSpeedPolicy {
    pub min_generation_ms: u64,
}
impl OutputSpeedPolicy {
    pub fn embedded() -> Self {
        embedded("output_speed")
    }
}
/// The reviewed reference table, parsed ONCE (was re-parsed on every call). A parse
/// failure yields `Value::Null`, so every lookup falls to `Default` — all-zero caps,
/// i.e. every label dropped: the fail-closed direction for customer-supplied text,
/// and the seed tests catch a malformed table before it ships.
static EMBEDDED_PLANS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json")).unwrap_or(Value::Null)
});

fn embedded<T: serde::de::DeserializeOwned + Default>(key: &str) -> T {
    serde_json::from_value(EMBEDDED_PLANS["policy"][key].clone()).unwrap_or_default()
}
#[derive(Debug, Clone, Default)]
pub struct RawLabels {
    pub metadata_json: Option<String>,
    pub metadata: Vec<(String, Value)>,
    pub tags: Vec<String>,
    pub environment: Option<String>,
    pub release: Option<String>,
    pub service: Option<String>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labels {
    pub metadata: BTreeMap<String, String>,
    pub tags: Vec<String>,
    pub environment: Option<String>,
    pub release: Option<String>,
    pub service: Option<String>,
}
impl Labels {
    pub fn write_to(&self, attributes: &mut crate::SpanAttributes, dropped: &Dropped) {
        attributes.tracelane_metadata = (!self.metadata.is_empty()).then(|| self.metadata.clone());
        attributes.tracelane_tags = (!self.tags.is_empty()).then(|| self.tags.clone());
        attributes.deployment_environment = self.environment.clone();
        attributes.service_version = self.release.clone();
        attributes.service_name = self.service.clone();
        attributes.tracelane_labels_dropped = (!dropped.is_empty()).then(|| dropped.clone());
    }
}
pub type Dropped = BTreeMap<String, usize>;
pub fn bound_labels(mut raw: RawLabels, caps: &LabelCaps) -> (Labels, Dropped) {
    let mut labels = Labels::default();
    let mut dropped = Dropped::default();
    if let Some(json) = raw.metadata_json {
        // Check bytes before parsing, including invalid JSON and huge headers.
        if json.len() > caps.max_metadata_total_bytes {
            bump(&mut dropped, "metadata_keys");
        } else if let Ok(entries) = parse_metadata(&json) {
            raw.metadata.extend(entries);
        } else {
            bump(&mut dropped, "metadata_keys");
        }
    }
    for (key, value) in raw.metadata {
        let value = match value {
            Value::String(s) => Some(s),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        };
        let Some(value) = value.filter(|v| v.len() <= caps.max_value_bytes) else {
            bump(&mut dropped, "metadata_keys");
            continue;
        };
        if !valid_key(&key, caps.max_key_bytes) {
            bump(&mut dropped, "metadata_keys");
            continue;
        }
        if labels.metadata.contains_key(&key) {
            continue;
        }
        if labels.metadata.len() >= caps.max_metadata_keys {
            bump(&mut dropped, "metadata_keys");
            continue;
        }
        labels.metadata.insert(key, value);
    }
    for tag in raw.tags {
        let tag = tag.trim();
        if tag.is_empty() || labels.tags.iter().any(|v| v == tag) {
            continue;
        }
        if tag.len() > caps.max_tag_bytes || !printable(tag) || labels.tags.len() >= caps.max_tags {
            bump(&mut dropped, "tags");
            continue;
        }
        labels.tags.push(tag.to_owned());
    }
    labels.environment = bound_text(
        raw.environment,
        caps.max_environment_bytes,
        true,
        "environment",
        &mut dropped,
    );
    labels.release = bound_text(
        raw.release,
        caps.max_release_bytes,
        false,
        "release",
        &mut dropped,
    );
    labels.service = bound_text(
        raw.service,
        caps.max_service_bytes,
        false,
        "service",
        &mut dropped,
    );
    (labels, dropped)
}
fn bump(dropped: &mut Dropped, key: &str) {
    *dropped.entry(key.to_owned()).or_default() += 1;
}
pub fn valid_key(key: &str, cap: usize) -> bool {
    !key.is_empty()
        && key.len() <= cap
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn printable(text: &str) -> bool {
    !text.chars().any(char::is_control)
}
fn bound_text(
    raw: Option<String>,
    cap: usize,
    lower: bool,
    key: &str,
    dropped: &mut Dropped,
) -> Option<String> {
    let raw = raw?;
    let value = if lower {
        raw.trim().to_lowercase()
    } else {
        raw.trim().to_owned()
    };
    if value.is_empty() {
        return None;
    }
    if value.len() > cap || !printable(&value) {
        bump(dropped, key);
        None
    } else {
        Some(value)
    }
}
// A map visitor preserves wire order without changing serde_json's global map type.
fn parse_metadata(raw: &str) -> Result<Vec<(String, Value)>, serde_json::Error> {
    #[cfg(test)]
    PARSES.with(|n| n.set(n.get() + 1));
    struct Object;
    impl<'de> serde::de::Visitor<'de> for Object {
        type Value = Vec<(String, Value)>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a flat metadata object")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut values = Vec::new();
            while let Some(entry) = map.next_entry()? {
                values.push(entry);
            }
            Ok(values)
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(raw);
    let values = serde::Deserializer::deserialize_map(&mut decoder, Object)?;
    decoder.end()?;
    Ok(values)
}
#[cfg(test)]
thread_local! { static PARSES:std::cell::Cell<usize>=const {std::cell::Cell::new(0)}; }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn label_bounds_keep_arrival_order_normalize_and_count() {
        let caps = LabelCaps::embedded();
        let raw = RawLabels {
            metadata_json: Some(format!(
                "{{{}}}",
                (0..17)
                    .rev()
                    .map(|i| format!("\"k{i}\":{i}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            tags: vec![
                " beta ".into(),
                "beta".into(),
                "bad\n".into(),
                "x".repeat(65),
            ],
            environment: Some(" Production ".into()),
            release: Some("x".repeat(129)),
            service: Some("api".into()),
            ..Default::default()
        };
        let (labels, dropped) = bound_labels(raw, &caps);
        assert_eq!(labels.metadata.len(), 16);
        assert!(!labels.metadata.contains_key("k0"));
        assert_eq!(labels.metadata["k16"], "16");
        assert_eq!(labels.environment.as_deref(), Some("production"));
        assert_eq!(labels.release, None);
        assert_eq!(labels.tags, vec!["beta", "bad"]);
        assert_eq!(dropped["metadata_keys"], 1);
        assert_eq!(dropped["release"], 1);
        assert_eq!(dropped["tags"], 1);
        assert_eq!(OutputSpeedPolicy::embedded().min_generation_ms, 50);
    }
    #[test]
    fn oversized_metadata_never_reaches_the_json_parser() {
        let caps = LabelCaps::embedded();
        for bytes in [3072, 1024 * 1024] {
            PARSES.with(|n| n.set(0));
            let (labels, dropped) = bound_labels(
                RawLabels {
                    metadata_json: Some("[".repeat(bytes)),
                    ..Default::default()
                },
                &caps,
            );
            assert!(labels.metadata.is_empty());
            assert_eq!(dropped["metadata_keys"], 1);
            assert_eq!(PARSES.with(|n| n.get()), 0);
        }
    }
    #[test]
    fn invalid_label_shapes_never_fail_the_request() {
        let caps = LabelCaps::embedded();
        let (labels, dropped) = bound_labels(
            RawLabels {
                metadata_json: Some(
                    r#"{"nested":{},"array":[],"null":null,"bool":true,"n":2.5,"bad key":"x"}"#
                        .into(),
                ),
                environment: Some("a\nb".into()),
                ..Default::default()
            },
            &caps,
        );
        assert_eq!(
            labels.metadata,
            BTreeMap::from([("bool".into(), "true".into()), ("n".into(), "2.5".into())])
        );
        assert_eq!(dropped["metadata_keys"], 4);
        assert_eq!(labels.environment, None);
        let (_, dropped) = bound_labels(
            RawLabels {
                metadata_json: Some("[oops".into()),
                ..Default::default()
            },
            &caps,
        );
        assert_eq!(dropped["metadata_keys"], 1);
    }
}
