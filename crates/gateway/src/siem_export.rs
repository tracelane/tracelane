//! Minimized tenant evidence envelopes and bounded, SSRF-guarded SIEM delivery.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use tracelane_audit_verifier::action::Envelope;
use tracelane_shared::TracelaneSpan;
use uuid::Uuid;

const SCHEMA: &str = "https://opentelemetry.io/schemas/1.41.1";
const OCSF_VERSION: &str = "1.4.0";
const SENTINEL_API_VERSION: &str = "2023-01-01";
// Explicit metadata subset. Never copy unknown attributes, prompts, arguments or results.
const SPAN_FIELDS: &[&str] = &[
    "gen_ai_operation_name",
    "gen_ai_provider_name",
    "gen_ai_request_model",
    "gen_ai_response_model",
    "gen_ai_response_id",
    "gen_ai_usage_input_tokens",
    "gen_ai_usage_output_tokens",
    "gen_ai_usage_cache_read_input_tokens",
    "gen_ai_usage_cache_creation_input_tokens",
    "gen_ai_usage_reasoning_output_tokens",
    "gen_ai_request_stream",
    "gen_ai_tool_call_id",
];
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Connector {
    Splunk,
    Sentinel,
    Ocsf,
}
pub fn connector(name: &str) -> Result<Connector> {
    match name {
        "splunk" => Ok(Connector::Splunk),
        "sentinel" => Ok(Connector::Sentinel),
        "ocsf" => Ok(Connector::Ocsf),
        _ => anyhow::bail!("unknown SIEM format"),
    }
}
pub fn credential<'a>(
    kind: Connector,
    mut headers: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<secrecy::SecretString> {
    let (name, value) = headers.next().context("missing SIEM credential")?;
    ensure!(
        headers.next().is_none() && name == "authorization",
        "invalid SIEM credential headers"
    );
    let prefix = if kind == Connector::Splunk {
        "Splunk "
    } else {
        "Bearer "
    };
    let value = value
        .strip_prefix(prefix)
        .context("invalid SIEM credential scheme")?;
    ensure!(
        !value.is_empty() && !value.bytes().any(|b| b.is_ascii_whitespace()),
        "invalid SIEM credential"
    );
    Ok(secrecy::SecretString::from(value.to_owned()))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub tenant: Uuid,
    pub id: Uuid,
    pub time: DateTime<Utc>,
    pub event: String,
    pub attributes: Value,
}
pub fn span_record(s: &TracelaneSpan) -> Result<Record> {
    let source = serde_json::to_value(&s.attributes)?;
    let mut attributes = serde_json::Map::new();
    for field in SPAN_FIELDS {
        if let Some(v) = source.get(field).filter(|v| !v.is_null()) {
            let key = tracelane_shared::otlp::encode::semconv_key(field)
                .context("unknown SIEM attribute")?;
            attributes.insert(key.into(), v.clone());
        }
    }
    attributes.insert("tracelane.trace_id".into(), json!(s.trace_id));
    use sha2::Digest;
    let identity = serde_json::to_vec(&(
        "tracelane.siem-span.v1",
        s.tenant_id.as_uuid(),
        s.trace_id,
        s.span_id,
        s.start_time,
        &attributes,
    ))?;
    let digest = sha2::Sha256::digest(identity);
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(Record {
        tenant: *s.tenant_id.as_uuid(),
        id: Uuid::from_bytes(id),
        time: s.start_time,
        event: "span".into(),
        attributes: Value::Object(attributes),
    })
}
pub fn action_record(tenant: Uuid, a: &Envelope) -> Result<Record> {
    ensure!(tenant == a.tenant_id, "SIEM source tenant mismatch");
    let body = serde_json::to_value(&a.body)?;
    let event = body["event_type"].as_str().context("missing action type")?;
    let mut attributes =
        json!({"tracelane.action_id":a.action_id,"tracelane.request_digest":a.request_digest});
    if event.starts_with("execution_") {
        attributes["gen_ai.operation.name"] = json!("execute_tool");
    }
    for name in [
        "decision",
        "reason_codes",
        "reason",
        "policy_id",
        "policy_version",
        "policy_hash",
        "tool_ref",
        "execution_id",
    ] {
        if let Some(v) = body.get(name) {
            attributes[format!("tracelane.{name}")] = v.clone();
        }
    }
    if let Some(key) = a.agent_key_id {
        attributes["tracelane.agent_key_id"] = json!(key);
    }
    Ok(Record {
        tenant,
        id: a.event_id,
        time: a.occurred_at,
        event: event.into(),
        attributes,
    })
}
pub fn payload(kind: Connector, r: &Record) -> Result<Value> {
    ensure!(r.attributes.is_object(), "invalid SIEM attributes");
    Ok(match kind {
        Connector::Splunk => {
            json!({"time":r.time.timestamp_millis() as f64/1000.0,"source":"tracelane","sourcetype":"tracelane:genai","event":{"id":r.id,"tenant_id":r.tenant,"event":r.event,"schema_url":SCHEMA,"attributes":r.attributes}})
        }
        Connector::Sentinel => {
            json!([{"TimeGenerated":r.time.to_rfc3339(),"RecordId":r.id,"TenantId":r.tenant,"Event":r.event,"SchemaUrl":SCHEMA,"Attributes":r.attributes}])
        }
        // This is OCSF-shaped evidence, not a claim that unavailable source endpoint
        // fields were observed. The exporter application is distinct from a user.
        Connector::Ocsf => {
            json!({"class_uid":6003,"category_uid":6,"activity_id":99,"type_uid":600399,"severity_id":1,"time":r.time.timestamp_millis(),"metadata":{"version":OCSF_VERSION,"product":{"name":"Tracelane","vendor_name":"Tracelane"},"uid":r.id},"actor":{"app_name":"Tracelane evidence exporter"},"api":{"operation":r.event},"unmapped":{"tenant_id":r.tenant,"schema_url":SCHEMA,"attributes":r.attributes}})
        }
    })
}
pub fn validate_destination(kind: Connector, raw: &str) -> Result<reqwest::Url> {
    ensure!(
        raw.len() <= crate::otel_export::config().max_url_bytes,
        "SIEM URL too long"
    );
    let u = reqwest::Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid SIEM URL"))?;
    let https = u.scheme() == "https";
    #[cfg(test)]
    let https = https
        || (u.scheme() == "http"
            && u.host_str()
                .is_some_and(|s| matches!(s, "127.0.0.1" | "[::1]")));
    ensure!(
        https
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none(),
        "invalid SIEM URL"
    );
    match kind {
        Connector::Splunk => ensure!(
            u.path().ends_with("/services/collector/event"),
            "invalid HEC path"
        ),
        Connector::Sentinel => {
            let p: Vec<_> = u.path().split('/').collect();
            ensure!(
                p.len() == 5
                    && p[1] == "dataCollectionRules"
                    && p[3] == "streams"
                    && [p[2], p[4]].iter().all(|s| !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
                "invalid Logs Ingestion path"
            );
        }
        Connector::Ocsf => {}
    }
    Ok(u)
}
pub struct Destination {
    pub tenant: Uuid,
    pub id: Uuid,
    pub kind: Connector,
    pub url: String,
    pub credential: secrecy::SecretString,
}
#[derive(Clone)]
pub struct DeliveryConfig {
    pub timeout: Duration,
    pub max_bytes: usize,
    pub retry_delays: Vec<Duration>,
}
/// One send, including DNS and response validation, bounded by the outer timeout.
async fn send(d: &Destination, r: &Record, c: &DeliveryConfig, body: &[u8]) -> Result<()> {
    let mut url = validate_destination(d.kind, &d.url)?;
    let target = crate::ssrf_guard::validate_url_pinned(url.as_str())
        .await
        .context("SIEM destination refused")?;
    if d.kind == Connector::Sentinel {
        url.query_pairs_mut()
            .append_pair("api-version", SENTINEL_API_VERSION);
    }
    let client = target
        .pin(crate::ssrf_guard::safe_client_builder().no_proxy())
        .timeout(c.timeout)
        .build()?;
    let scheme = if d.kind == Connector::Splunk {
        "Splunk"
    } else {
        "Bearer"
    };
    let mut auth = reqwest::header::HeaderValue::from_str(&format!(
        "{scheme} {}",
        d.credential.expose_secret()
    ))
    .map_err(|_| anyhow::anyhow!("invalid SIEM credential"))?;
    auth.set_sensitive(true);
    let mut reply = client
        .post(url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .header("Content-Type", "application/json")
        .header("X-Tracelane-Delivery-Id", format!("{}:{}", d.id, r.id))
        .body(body.to_vec())
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;
    ensure!(reply.status().is_success(), "SIEM HTTP failure");
    if d.kind == Connector::Splunk {
        let mut bytes = Vec::new();
        while let Some(chunk) = reply.chunk().await.map_err(reqwest::Error::without_url)? {
            ensure!(
                chunk.len() <= c.max_bytes.saturating_sub(bytes.len()),
                "SIEM response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let v: Value = serde_json::from_slice(&bytes).context("invalid HEC response")?;
        ensure!(v["code"].as_u64() == Some(0), "HEC application failure");
    }
    Ok(())
}
/// Bounded delivery attempts. Only background workers call this; no request-path await.
pub async fn deliver(d: &Destination, r: &Record, c: &DeliveryConfig) -> Result<usize> {
    ensure!(d.tenant == r.tenant, "SIEM destination tenant mismatch");
    ensure!(
        !c.timeout.is_zero()
            && c.max_bytes > 0
            && std::time::Instant::now().checked_add(c.timeout).is_some(),
        "invalid SIEM delivery bounds"
    );
    ensure!(
        c.retry_delays
            .iter()
            .all(|d| !d.is_zero() && std::time::Instant::now().checked_add(*d).is_some()),
        "invalid SIEM retry schedule"
    );
    ensure!(
        !d.credential.expose_secret().is_empty()
            && d.credential.expose_secret().len()
                <= crate::otel_export::config().max_header_value_bytes,
        "invalid SIEM credential"
    );
    validate_destination(d.kind, &d.url)?;
    let body = serde_json::to_vec(&payload(d.kind, r)?)?;
    ensure!(body.len() <= c.max_bytes, "SIEM record too large");
    for attempt in 0..=c.retry_delays.len() {
        if tokio::time::timeout(c.timeout, send(d, r, c, &body))
            .await
            .is_ok_and(|r| r.is_ok())
        {
            return Ok(attempt + 1);
        }
        if let Some(delay) = c.retry_delays.get(attempt) {
            tokio::time::sleep(*delay).await;
        }
    }
    anyhow::bail!("SIEM delivery exhausted")
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod pg_tests;
pub(crate) mod worker;
