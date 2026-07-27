//! rrweb DOM event enricher for browser-agent spans.
//!
//! Browser agents using Playwright or Puppeteer can emit rrweb DOM events
//! as OTLP span attributes. This enricher reads those events and computes
//! derived span attributes:
//!
//!   `tracelane.browser.dom_hash`          — SHA-256 of the full DOM snapshot
//!   `tracelane.browser.dom_mutation_score` — 0.0–1.0, ratio of mutated nodes
//!   `tracelane.browser.screenshot_url`    — URL of screenshot in R2
//!   `tracelane.browser.captcha_detected`  — bool, set by captcha heuristics
//!   `tracelane.browser.step_index`        — current step in the agent loop
//!
//! Enrichment happens in the ingest hot path, inline, before the span is
//! written to ClickHouse. Computationally cheap: SHA-256 hash + DOM diff counter.
//!
//! rrweb event format: https://github.com/rrweb-io/rrweb/blob/master/docs/serialization.md

use anyhow::Result;
use ring::digest;
use serde_json::{Value, json};
use tracing::instrument;

/// rrweb event types we care about.
/// Full list: https://github.com/rrweb-io/rrweb (type field values)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrwebEventType {
    /// Type 4: full DOM snapshot
    FullSnapshot,
    /// Type 3: incremental snapshot (mutations, mouse moves, input, etc.)
    IncrementalSnapshot,
    /// Type 2: meta (document URL, viewport size)
    Meta,
    /// Unknown
    Other(u64),
}

impl From<u64> for RrwebEventType {
    fn from(n: u64) -> Self {
        match n {
            2 => Self::Meta,
            3 => Self::IncrementalSnapshot,
            4 => Self::FullSnapshot,
            n => Self::Other(n),
        }
    }
}

/// An rrweb event as parsed from the span attribute `tracelane.browser.rrweb_events`.
#[derive(Debug, Clone)]
pub struct RrwebEvent {
    pub event_type: RrwebEventType,
    pub timestamp_ms: i64,
    /// Raw event data (serde_json::Value)
    pub data: Value,
}

impl RrwebEvent {
    pub fn from_json(v: &Value) -> Option<Self> {
        let event_type = v.get("type")?.as_u64().map(RrwebEventType::from)?;
        let timestamp_ms = v.get("timestamp")?.as_i64().unwrap_or(0);
        let data = v.get("data").cloned().unwrap_or(Value::Null);
        Some(Self {
            event_type,
            timestamp_ms,
            data,
        })
    }
}

/// Result of enriching a span with rrweb events.
#[derive(Debug, Clone, Default)]
pub struct BrowserEnrichment {
    /// SHA-256 hex of the most recent full DOM snapshot (64 chars)
    pub dom_hash: Option<String>,
    /// Fraction of DOM nodes mutated since last full snapshot (0.0–1.0)
    pub dom_mutation_score: Option<f64>,
    /// Whether a CAPTCHA was detected in the DOM
    pub captcha_detected: bool,
    /// URL of the current page (from Meta event)
    pub page_url: Option<String>,
}

impl BrowserEnrichment {
    /// Convert to a map of OTLP span attributes.
    pub fn to_span_attrs(&self) -> Vec<(String, Value)> {
        let mut attrs = Vec::new();
        if let Some(ref hash) = self.dom_hash {
            attrs.push(("tracelane.browser.dom_hash".to_string(), json!(hash)));
        }
        if let Some(score) = self.dom_mutation_score {
            attrs.push((
                "tracelane.browser.dom_mutation_score".to_string(),
                json!(score),
            ));
        }
        attrs.push((
            "tracelane.browser.captcha_detected".to_string(),
            json!(self.captcha_detected),
        ));
        if let Some(ref url) = self.page_url {
            attrs.push(("tracelane.browser.page_url".to_string(), json!(url)));
        }
        attrs
    }
}

/// Enrich a span's attributes by processing embedded rrweb events.
///
/// # Arguments
/// - `span_attrs` — current span attributes map (modified in place)
/// - `rrweb_events_json` — JSON array of rrweb events from span attribute
///   `tracelane.browser.rrweb_events`
///
/// # Returns
/// The enrichment result (also merged into `span_attrs`).
#[instrument(skip(span_attrs, rrweb_events_json))]
pub fn enrich_span(
    span_attrs: &mut serde_json::Map<String, Value>,
    rrweb_events_json: &Value,
) -> Result<BrowserEnrichment> {
    let events: Vec<RrwebEvent> = rrweb_events_json
        .as_array()
        .map(|arr| arr.iter().filter_map(RrwebEvent::from_json).collect())
        .unwrap_or_default();

    let enrichment = compute_enrichment(&events);

    for (key, val) in enrichment.to_span_attrs() {
        span_attrs.insert(key, val);
    }

    Ok(enrichment)
}

/// Compute browser enrichment from a sequence of rrweb events.
fn compute_enrichment(events: &[RrwebEvent]) -> BrowserEnrichment {
    let mut enrichment = BrowserEnrichment::default();

    // Find the most recent full snapshot and hash it
    let last_full_snapshot = events
        .iter()
        .rev()
        .find(|e| e.event_type == RrwebEventType::FullSnapshot);

    if let Some(snapshot) = last_full_snapshot {
        let snapshot_str = snapshot.data.to_string();
        let d = digest::digest(&digest::SHA256, snapshot_str.as_bytes());
        enrichment.dom_hash = Some(hex::encode(d.as_ref()));
    }

    // Count incremental snapshot mutations
    let snapshot_node_count = events
        .iter()
        .filter(|e| e.event_type == RrwebEventType::FullSnapshot)
        .filter_map(|e| e.data.get("node"))
        .filter_map(|n| count_nodes(n))
        .next()
        .unwrap_or(1); // avoid div-by-zero

    let mutation_count = events
        .iter()
        .filter(|e| e.event_type == RrwebEventType::IncrementalSnapshot)
        .filter_map(|e| e.data.get("adds"))
        .filter_map(|adds| adds.as_array())
        .map(|arr| arr.len())
        .sum::<usize>();

    if !events.is_empty() {
        enrichment.dom_mutation_score =
            Some((mutation_count as f64 / snapshot_node_count as f64).min(1.0));
    }

    // CAPTCHA detection: check Meta event URLs and snapshot text
    for event in events {
        if let Some(href) = event.data.get("href").and_then(Value::as_str) {
            if is_captcha_url(href) {
                enrichment.captcha_detected = true;
            }
            if event.event_type == RrwebEventType::Meta {
                enrichment.page_url = Some(href.to_string());
            }
        }

        // Check snapshot content for CAPTCHA signatures
        if event.event_type == RrwebEventType::FullSnapshot {
            let content = event.data.to_string();
            if content.contains("g-recaptcha")
                || content.contains("h-captcha")
                || content.contains("cf-turnstile")
                || content.contains("arkose-labs")
            {
                enrichment.captcha_detected = true;
            }
        }
    }

    enrichment
}

/// Count nodes in an rrweb serialised node tree (recursive).
fn count_nodes(node: &Value) -> Option<usize> {
    let mut count = 1usize;
    if let Some(children) = node.get("childNodes").and_then(Value::as_array) {
        for child in children {
            count += count_nodes(child).unwrap_or(0);
        }
    }
    Some(count)
}

fn is_captcha_url(url: &str) -> bool {
    let patterns = [
        "recaptcha",
        "hcaptcha",
        "cf-turnstile",
        "arkose-labs",
        "geetest",
        "funcaptcha",
    ];
    patterns.iter().any(|p| url.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_snapshot_event(node_count: usize) -> Value {
        let children: Vec<Value> = (0..node_count)
            .map(|i| json!({ "id": i, "type": 3, "tagName": "div", "childNodes": [] }))
            .collect();
        json!({
            "type": 4,
            "timestamp": 1000,
            "data": {
                "node": {
                    "id": 1,
                    "type": 0,
                    "childNodes": children
                }
            }
        })
    }

    fn incremental_snapshot_event(add_count: usize) -> Value {
        let adds: Vec<Value> = (0..add_count)
            .map(|i| json!({ "parentId": 1, "nextId": null, "node": { "id": 100+i } }))
            .collect();
        json!({
            "type": 3,
            "timestamp": 2000,
            "data": { "adds": adds }
        })
    }

    #[test]
    fn enrich_empty_events_returns_defaults() {
        let events: Vec<RrwebEvent> = vec![];
        let enrichment = compute_enrichment(&events);
        assert!(enrichment.dom_hash.is_none());
        assert!(enrichment.dom_mutation_score.is_none());
        assert!(!enrichment.captcha_detected);
    }

    #[test]
    fn full_snapshot_produces_dom_hash() {
        let raw = full_snapshot_event(10);
        let event = RrwebEvent::from_json(&raw).unwrap();
        assert_eq!(event.event_type, RrwebEventType::FullSnapshot);

        let enrichment = compute_enrichment(&[event]);
        assert!(enrichment.dom_hash.is_some());
        assert_eq!(enrichment.dom_hash.as_deref().unwrap().len(), 64);
    }

    #[test]
    fn incremental_adds_compute_mutation_score() {
        let snap = RrwebEvent::from_json(&full_snapshot_event(10)).unwrap();
        let incr = RrwebEvent::from_json(&incremental_snapshot_event(5)).unwrap();
        let enrichment = compute_enrichment(&[snap, incr]);
        let score = enrichment.dom_mutation_score.unwrap();
        assert!(score > 0.0);
        assert!(score <= 1.0);
    }

    #[test]
    fn captcha_url_detected_from_href() {
        let raw = json!({
            "type": 2,
            "timestamp": 500,
            "data": { "href": "https://www.google.com/recaptcha/api/siteverify" }
        });
        let event = RrwebEvent::from_json(&raw).unwrap();
        let enrichment = compute_enrichment(&[event]);
        assert!(enrichment.captcha_detected);
    }

    #[test]
    fn captcha_detected_from_snapshot_content() {
        let raw = json!({
            "type": 4,
            "timestamp": 1000,
            "data": {
                "node": {
                    "id": 1, "type": 0,
                    "childNodes": [{
                        "id": 2, "type": 1, "tagName": "div",
                        "attributes": { "class": "g-recaptcha" },
                        "childNodes": []
                    }]
                }
            }
        });
        let event = RrwebEvent::from_json(&raw).unwrap();
        let enrichment = compute_enrichment(&[event]);
        assert!(enrichment.captcha_detected);
    }

    #[test]
    fn to_span_attrs_includes_all_fields() {
        let enrichment = BrowserEnrichment {
            dom_hash: Some("abc123".to_string()),
            dom_mutation_score: Some(0.5),
            captcha_detected: true,
            page_url: Some("https://example.com".to_string()),
        };
        let attrs = enrichment.to_span_attrs();
        let keys: Vec<&str> = attrs.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"tracelane.browser.dom_hash"));
        assert!(keys.contains(&"tracelane.browser.dom_mutation_score"));
        assert!(keys.contains(&"tracelane.browser.captcha_detected"));
        assert!(keys.contains(&"tracelane.browser.page_url"));
    }
}
