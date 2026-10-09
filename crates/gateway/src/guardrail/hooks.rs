//! Signed, bounded custom guardrails over tenant-owned HTTPS endpoints.
use super::outcome::RailOutcome;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    #[default]
    Closed,
    Open,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<super::adapters::Adapter>,
    pub pre: bool,
    pub post: bool,
    pub timeout_ms: u64,
    #[serde(default)]
    pub fail_mode: FailMode,
}
impl Config {
    pub fn credential_key(&self, id: Uuid) -> String {
        let identity = credential_key(id, &self.endpoint);
        match &self.adapter {
            Some(adapter) => format!("{}:{identity}", adapter.kind()),
            None => identity,
        }
    }
    pub fn credential_valid(&self, secret: &SecretString) -> bool {
        use secrecy::ExposeSecret;
        let Some(cap) = limits() else { return false };
        let value = secret.expose_secret();
        !value.is_empty()
            && value.len() <= cap.secret_bytes
            && if self.adapter.is_some() {
                reqwest::header::HeaderValue::from_str(value).is_ok()
            } else {
                value.len() >= cap.min_secret_bytes
            }
    }
    pub fn valid(&self) -> bool {
        let Some(limits) = limits() else { return false };
        let Ok(url) = reqwest::Url::parse(&self.endpoint) else {
            return false;
        };
        (self.pre || self.post)
            && self.timeout_ms > 0
            && self.timeout_ms <= limits.timeout_ms
            && url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && self
                .adapter
                .as_ref()
                .is_none_or(|a| a.valid(&self.endpoint))
    }
}
#[derive(Clone)]
pub struct Hook {
    pub id: Uuid,
    pub config: Config,
    pub ciphertext: String,
    pub secret: Arc<SecretString>,
    #[cfg(test)]
    pub answer: Option<TestAnswer>,
}
impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hook")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
impl PartialEq for Hook {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.config == other.config && self.ciphertext == other.ciphertext
    }
}
impl Eq for Hook {}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Pre,
    Post,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Allow {},
    Deny {},
    Redact { matches: Vec<String> },
}
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub hook_id: Uuid,
    pub phase: Phase,
    pub fail_mode: FailMode,
    pub outcome: &'static str,
    pub reason: &'static str,
    pub latency_ms: u64,
}
pub struct Evaluation {
    pub outcome: RailOutcome,
    pub redactions: Vec<String>,
    pub event: Event,
}
#[derive(Deserialize)]
pub struct Limits {
    pub max_hooks: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub response_bytes: usize,
    pub max_matches: usize,
    pub match_bytes: usize,
    pub input_bytes: usize,
    pub secret_bytes: usize,
    pub min_secret_bytes: usize,
}
pub fn limits() -> Option<&'static Limits> {
    static LIMITS: std::sync::OnceLock<Option<Limits>> = std::sync::OnceLock::new();
    LIMITS
        .get_or_init(|| {
            let value: serde_json::Value =
                serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
            serde_json::from_value(value["policy"]["guardrail_hooks"].clone()).ok()
        })
        .as_ref()
}

pub fn parse_reply(bytes: &[u8]) -> Option<Reply> {
    let caps = limits()?;
    if bytes.len() > caps.response_bytes {
        return None;
    }
    let reply: Reply = serde_json::from_slice(bytes).ok()?;
    if let Reply::Redact { matches } = &reply {
        if matches.is_empty()
            || matches.len() > caps.max_matches
            || matches
                .iter()
                .any(|m| m.is_empty() || m.len() > caps.match_bytes)
        {
            return None;
        }
        let unique: std::collections::BTreeSet<_> = matches.iter().collect();
        if unique.len() != matches.len() {
            return None;
        }
    }
    Some(reply)
}
pub fn signed_body(hook: &Hook, phase: Phase, text: &str) -> (Vec<u8>, String) {
    use secrecy::ExposeSecret;
    let body = serde_json::json!({"request_id":Uuid::new_v4(),"timestamp":chrono::Utc::now().timestamp(),"phase":phase,"text":text}).to_string().into_bytes();
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        hook.secret.expose_secret().as_bytes(),
    );
    let signature = hex::encode(ring::hmac::sign(&key, &body).as_ref());
    (body, signature)
}
fn active() -> &'static std::sync::Mutex<std::collections::HashMap<Uuid, usize>> {
    static ACTIVE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<Uuid, usize>>> =
        std::sync::OnceLock::new();
    ACTIVE.get_or_init(Default::default)
}
pub struct Permit(Uuid);
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut active) = active().lock()
            && let Some(n) = active.get_mut(&self.0)
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                active.remove(&self.0);
            }
        }
    }
}
pub fn acquire(tenant: Uuid) -> Option<Permit> {
    let cap = limits()?.concurrency;
    let mut active = active().lock().ok()?;
    let n = active.entry(tenant).or_default();
    if *n >= cap {
        return None;
    }
    *n += 1;
    Some(Permit(tenant))
}

/// Fail-CLOSED for invalid destinations and malformed replies. Only operational
/// failures use the explicitly selected fail-open mode. No upstream text is logged.
async fn exchange(hook: &Hook, phase: Phase, text: &str) -> Result<Reply, &'static str> {
    let caps = limits().ok_or("HOOK_CONFIGURATION_INVALID")?;
    let wire = if hook.config.adapter.is_some() {
        super::adapters::request(hook, phase, text).ok_or("HOOK_ADAPTER_INPUT_INVALID")?
    } else {
        let (body, signature) = signed_body(hook, phase, text);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-tracelane-signature",
            reqwest::header::HeaderValue::from_str(&signature)
                .map_err(|_| "HOOK_CONFIGURATION_INVALID")?,
        );
        super::adapters::Outbound {
            url: hook.config.endpoint.clone(),
            body,
            headers,
        }
    };
    let parse = |bytes: &[u8]| match &hook.config.adapter {
        Some(adapter) => super::adapters::parse_reply(adapter, bytes),
        None => parse_reply(bytes),
    };
    #[cfg(test)]
    if let Some(answer) = &hook.answer {
        if answer.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(answer.delay_ms)).await;
        }
        if answer.transport_error {
            return Err("HOOK_TRANSPORT");
        }
        return parse(&answer.bytes).ok_or("HOOK_MALFORMED");
    }
    let target = crate::ssrf_guard::validate_url_pinned(&wire.url)
        .await
        .map_err(|_| "HOOK_DESTINATION_INVALID")?;
    let client = target
        .pin(crate::ssrf_guard::safe_client_builder().no_proxy())
        .build()
        .map_err(|_| "HOOK_TRANSPORT")?;
    let mut response = wire
        .into_request(&client, hook)
        .send()
        .await
        .map_err(|_| "HOOK_TRANSPORT")?;
    if !response.status().is_success() {
        return Err("HOOK_TRANSPORT");
    }
    if response
        .content_length()
        .is_some_and(|n| n > caps.response_bytes as u64)
    {
        return Err("HOOK_MALFORMED");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "HOOK_TRANSPORT")? {
        if bytes.len().saturating_add(chunk.len()) > caps.response_bytes {
            return Err("HOOK_MALFORMED");
        }
        bytes.extend_from_slice(&chunk);
    }
    parse(&bytes).ok_or("HOOK_MALFORMED")
}
pub async fn evaluate(tenant: Uuid, hook: &Hook, phase: Phase, text: &str) -> Evaluation {
    let start = std::time::Instant::now();
    let mut redactions = Vec::new();
    let result = if !hook.config.valid() {
        Err("HOOK_CONFIGURATION_INVALID")
    } else if limits().is_none_or(|l| text.len() > l.input_bytes) {
        Err("HOOK_INPUT_TOO_LARGE")
    } else if let Some(_permit) = acquire(tenant) {
        match tokio::time::timeout(
            std::time::Duration::from_millis(hook.config.timeout_ms),
            exchange(hook, phase, text),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err("HOOK_TIMEOUT"),
        }
    } else {
        Err("HOOK_OVERLOAD")
    };
    let (outcome, label, reason) = match result {
        Ok(Reply::Allow {}) => (RailOutcome::allow(), "allow", "HOOK_ALLOW"),
        Ok(Reply::Deny {}) => (RailOutcome::block("HOOK_DENY"), "block", "HOOK_DENY"),
        Ok(Reply::Redact { matches }) if matches.iter().all(|m| text.contains(m)) => {
            redactions = matches;
            (RailOutcome::redact("HOOK_REDACT"), "redact", "HOOK_REDACT")
        }
        Ok(Reply::Redact { .. }) => (
            RailOutcome::block("HOOK_MALFORMED"),
            "block",
            "HOOK_MALFORMED",
        ),
        Err(reason @ ("HOOK_TIMEOUT" | "HOOK_TRANSPORT" | "HOOK_OVERLOAD"))
            if hook.config.fail_mode == FailMode::Open =>
        {
            (RailOutcome::fail_open(reason), "fail_open", reason)
        }
        Err(reason) => (RailOutcome::block(reason), "block", reason),
    };
    let event = Event {
        hook_id: hook.id,
        phase,
        fail_mode: hook.config.fail_mode,
        outcome: label,
        reason,
        latency_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
    };
    Evaluation {
        outcome,
        redactions,
        event,
    }
}

/// The span and its early-abort guard share these bounded, content-free events.
#[derive(Clone, Default)]
pub struct Events(Arc<std::sync::Mutex<Vec<Event>>>);
impl std::fmt::Debug for Events {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HookEvents(..)")
    }
}
impl Events {
    pub fn record(&self, events: &[Event]) {
        if let Ok(mut stored) = self.0.lock() {
            let cap = limits().map_or(0, |l| l.max_hooks.saturating_mul(2));
            let room = cap.saturating_sub(stored.len());
            stored.extend(events.iter().take(room).cloned());
        }
    }
    pub fn value(&self) -> Option<serde_json::Value> {
        let events = self.0.lock().ok()?;
        if events.is_empty() {
            None
        } else {
            serde_json::to_value(&*events).ok()
        }
    }
}
pub fn append(outcome: &mut super::dispatcher::SideOutcome, evaluation: &Evaluation) {
    let mut rail = evaluation.outcome.clone();
    rail.details = serde_json::json!({"hook_id":evaluation.event.hook_id,"phase":evaluation.event.phase,"fail_mode":evaluation.event.fail_mode});
    let micros = evaluation.event.latency_ms.saturating_mul(1000);
    outcome.records.push(super::dispatcher::RailRecord {
        rail: "custom_hook",
        policy_version: "hook@1",
        latency_micros: micros,
        outcome: rail,
    });
    outcome.total_latency_micros = outcome.total_latency_micros.saturating_add(micros);
    outcome.decision =
        super::outcome::Decision::from_outcomes(outcome.records.iter().map(|r| &r.outcome.outcome));
}
pub fn block(outcome: &mut super::dispatcher::SideOutcome, reason: &'static str) {
    outcome.records.push(super::dispatcher::RailRecord {
        rail: "custom_hook",
        policy_version: "hook@1",
        latency_micros: 0,
        outcome: RailOutcome::block(reason),
    });
    outcome.decision = super::outcome::Decision::Block;
}
/// The caller's text only, excluding wire-positioned opaque credentials/ciphertext.
pub fn request_text(
    request: &tracelane_shared::ChatRequest,
    relay: Option<&serde_json::Value>,
) -> Result<String, &'static str> {
    let value;
    let body = match relay {
        Some(v) => v,
        None => {
            value = serde_json::to_value(request).map_err(|_| "HOOK_INPUT_UNSCANNABLE")?;
            &value
        }
    };
    let cap = limits().ok_or("HOOK_CONFIGURATION_INVALID")?.input_bytes;
    let mut text = String::new();
    let stopped = super::egress::egress_leaves(body, &mut |leaf, _| match leaf {
        super::egress::Leaf::Unscannable => true,
        super::egress::Leaf::Text(s) => {
            // URL userinfo is a transport credential, not hook content.
            if reqwest::Url::parse(s)
                .is_ok_and(|u| !u.username().is_empty() || u.password().is_some())
            {
                return true;
            }
            if text.len().saturating_add(s.len()).saturating_add(1) > cap {
                return true;
            }
            text.push_str(s);
            text.push('\n');
            false
        }
    });
    if stopped {
        Err("HOOK_INPUT_UNSCANNABLE")
    } else {
        Ok(text)
    }
}
pub fn replace(text: &str, matches: &[String]) -> Result<String, super::egress::Unredactable> {
    if matches.is_empty() {
        return Ok(text.to_owned());
    }
    let ac = aho_corasick::AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(matches)
        .map_err(|_| super::egress::Unredactable)?;
    let cap = limits().ok_or(super::egress::Unredactable)?.input_bytes;
    let mut projected = text.len();
    for hit in ac.find_iter(text) {
        projected = projected
            .saturating_sub(hit.len())
            .saturating_add("[REDACTED:custom]".len());
        if projected > cap {
            return Err(super::egress::Unredactable);
        }
    }
    let out = ac.replace_all(text, &vec!["[REDACTED:custom]"; matches.len()]);
    if limits().is_none_or(|l| out.len() > l.input_bytes) {
        Err(super::egress::Unredactable)
    } else {
        Ok(out)
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct TestAnswer {
    pub bytes: Vec<u8>,
    pub delay_ms: u64,
    pub transport_error: bool,
}

#[cfg(test)]
pub fn fixture() -> Hook {
    Hook {
        id: Uuid::new_v4(),
        config: Config {
            endpoint: "https://hooks.example.com/check".into(),
            adapter: None,
            pre: true,
            post: false,
            timeout_ms: 20,
            fail_mode: FailMode::Closed,
        },
        ciphertext: "test-only".into(),
        secret: Arc::new(SecretString::from("0123456789abcdef0123456789abcdef")),
        answer: Some(TestAnswer {
            bytes: br#"{"decision":"deny"}"#.to_vec(),
            delay_ms: 0,
            transport_error: false,
        }),
    }
}

pub(crate) fn credential_key(id: Uuid, endpoint: &str) -> String {
    format!("{id}:{endpoint}")
}
pub(crate) use crate::byok::guardrail_hook_aad as credential_aad;
