//! `OG-24` — spend threshold alerts: email, Slack, signed webhook. Spec:
//! `specs/OG-24-spend-alerts.md`.
//!
//! **Never on the request path.** `budgets::record_span` detects a crossing and calls
//! [`enqueue`] — a `try_send` into a bounded queue that never waits; a full queue is
//! refused and the crossing is retried on the next recorded request (the "fired" bit is
//! set only once a crossing is queued). ONE background task ([`spawn`]) moves crossings
//! into the Postgres outbox (`db::spend_alerts::enqueue`, `ON CONFLICT DO NOTHING` — the
//! dedup that holds across restarts) and delivers due rows, marking `delivered` only
//! after a 2xx (at-least-once; act → confirm → record, `.claude/rules/logging.md`).
//!
//! **Every outbound URL** goes through the SSRF guard with DNS pinning
//! (`ssrf_guard::validate_url_pinned` + `safe_client_builder`), at create time and at
//! every delivery; a `reqwest` error is stripped of its URL before it becomes a string.
//!
//! **Webhook signature** — `X-Tracelane-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret,
//! "<t>.<body>")>`, plus `X-Tracelane-Timestamp` and `X-Tracelane-Event-Id` (stable across
//! retries). A receiver verifies with a constant-time compare and a 300-second replay
//! window; [`verify_signature`] is the reference implementation.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use ring::hmac;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::budgets::Crossing;

/// HTTP bound on one delivery (the ADR-059 bound).
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
/// DNS-validation bound.
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a claimed delivery is leased before another claim may take it.
const LEASE_SECS: i64 = 300;

type Queue = (
    mpsc::Sender<Crossing>,
    Mutex<Option<mpsc::Receiver<Crossing>>>,
);

fn queue() -> &'static Queue {
    static Q: OnceLock<Queue> = OnceLock::new();
    Q.get_or_init(|| {
        let (tx, rx) = mpsc::channel(crate::controls::config().alert_queue_capacity);
        (tx, Mutex::new(Some(rx)))
    })
}

/// Queue a crossing. Never waits. `false` = the queue is full (or no worker will ever
/// read it): the caller does not mark the threshold fired, so it is retried.
pub(crate) fn enqueue(c: &Crossing) -> bool {
    queue().0.try_send(c.clone()).is_ok()
}

// ── Signing ──────────────────────────────────────────────────────────────────

/// `t=<ts>,v1=<hex>` over `"<ts>.<body>"`.
#[must_use]
pub(crate) fn sign(secret: &SecretString, ts: i64, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose_secret().as_bytes());
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(ts.to_string().as_bytes());
    ctx.update(b".");
    ctx.update(body);
    format!("t={ts},v1={}", hex::encode(ctx.sign().as_ref()))
}

/// The receiver's check, as documented to customers: parse `t` and `v1`, refuse a
/// timestamp more than `window_secs` from `now`, and compare the HMAC in constant time
/// (`ring::hmac::verify`). The gateway never RECEIVES its own webhooks, so this is the
/// reference implementation the tests prove the signature against — test-only.
#[cfg(test)]
#[must_use]
pub(crate) fn verify_signature(
    secret: &SecretString,
    header: &str,
    body: &[u8],
    now: i64,
    window_secs: i64,
) -> bool {
    let mut ts: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;
    for part in header.split(',').take(4) {
        match part.trim().split_once('=') {
            Some(("t", v)) => ts = v.parse().ok(),
            Some(("v1", v)) => sig = hex::decode(v).ok(),
            _ => {}
        }
    }
    let (Some(ts), Some(sig)) = (ts, sig) else {
        return false;
    };
    if (now - ts).abs() > window_secs {
        return false;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose_secret().as_bytes());
    let mut msg = ts.to_string().into_bytes();
    msg.push(b'.');
    msg.extend_from_slice(body);
    hmac::verify(&key, &msg, &sig).is_ok()
}

/// A fresh signing secret: `whsec_` + 32 random bytes, hex.
///
/// # Errors
/// The system RNG failed.
pub(crate) fn new_signing_secret() -> anyhow::Result<SecretString> {
    use ring::rand::SecureRandom as _;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| anyhow::anyhow!("RNG failure generating a signing secret"))?;
    Ok(SecretString::from(format!("whsec_{}", hex::encode(b))))
}

/// The AAD binding a channel's sealed secret to its row.
pub(crate) fn channel_aad(tenant: uuid::Uuid, id: uuid::Uuid) -> Vec<u8> {
    format!("spend-alert-channel:{tenant}:{id}").into_bytes()
}

// ── Delivery ─────────────────────────────────────────────────────────────────

/// Why a delivery did not land. Never contains a URL or a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeliveryError {
    /// The SSRF guard refused the URL — nothing left the box.
    Rejected(String),
    Unreachable(String),
    Status(u16),
    /// No mail provider configured (`RESEND_API_KEY`).
    EmailUnconfigured,
    /// The sealed secret could not be opened (no master key, or tampered).
    Secret(String),
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(m) => write!(f, "URL rejected by the SSRF guard: {m}"),
            Self::Unreachable(m) => write!(f, "unreachable: {m}"),
            Self::Status(s) => write!(f, "answered HTTP {s}"),
            Self::EmailUnconfigured => write!(f, "email_unconfigured"),
            Self::Secret(m) => write!(f, "channel secret unavailable: {m}"),
        }
    }
}

/// The mail settings (from `RESEND_API_KEY` / `RESEND_FROM`, read once at boot).
#[derive(Clone)]
pub(crate) struct Mail {
    pub api_key: Option<SecretString>,
    pub from: String,
}

impl Mail {
    pub(crate) fn from_env() -> Self {
        Self {
            api_key: std::env::var("RESEND_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
                .map(SecretString::from),
            from: std::env::var("RESEND_FROM").unwrap_or_else(|_| "alerts@tracelane.dev".into()),
        }
    }
}

/// The plain-text line an email or Slack message carries. Only numbers and labels —
/// never a prompt or a key.
pub(crate) fn message_text(payload: &Value) -> String {
    let s = |k: &str| payload.get(k).and_then(Value::as_str).unwrap_or("");
    let n = |k: &str| payload.get(k).and_then(Value::as_f64).unwrap_or(0.0);
    let who = match (
        s("scope"),
        payload.get("subject_id").and_then(Value::as_str),
    ) {
        ("workspace", _) => "the workspace".to_owned(),
        (scope, Some(id)) => format!("{scope} {id}"),
        (scope, None) => scope.to_owned(),
    };
    let eu = payload
        .get("end_user")
        .and_then(Value::as_str)
        .map(|u| format!(" for end user `{}`", u.chars().take(64).collect::<String>()))
        .unwrap_or_default();
    format!(
        "Tracelane spend alert — {who}{eu} reached {} of its {} {} budget: ${:.2} spent of \
         ${:.2} ({} mode).",
        s("threshold"),
        s("window"),
        s("policy"),
        n("spent_usd"),
        n("budget_usd"),
        s("mode"),
    )
}

/// POST a signed JSON body to a customer webhook through the SSRF guard (DNS-pinned).
///
/// # Errors
/// Fail-CLOSED on the report: `Ok` only for a 2xx.
pub(crate) async fn deliver_webhook(
    url: &str,
    secret: &SecretString,
    event_id: uuid::Uuid,
    body: &Value,
) -> Result<u16, DeliveryError> {
    let pinned = match tokio::time::timeout(
        VALIDATE_TIMEOUT,
        crate::ssrf_guard::validate_url_pinned(url),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => return Err(DeliveryError::Rejected(e.to_string())),
        Err(_) => {
            return Err(DeliveryError::Unreachable(
                "URL validation (DNS) timed out".into(),
            ));
        }
    };
    let client = pinned
        .pin(crate::ssrf_guard::safe_client_builder())
        .timeout(DELIVERY_TIMEOUT)
        .build()
        .map_err(|e| DeliveryError::Unreachable(format!("HTTP client build failed: {e}")))?;
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    let ts = chrono::Utc::now().timestamp();
    let resp = client
        .post(url)
        .header("content-type", "application/json")
        .header("x-tracelane-event-id", event_id.to_string())
        .header("x-tracelane-timestamp", ts.to_string())
        .header("x-tracelane-signature", sign(secret, ts, &bytes))
        .body(bytes)
        .send()
        .await
        .map_err(|e| DeliveryError::Unreachable(e.without_url().to_string()))?;
    let status = resp.status().as_u16();
    if resp.status().is_success() {
        Ok(status)
    } else {
        Err(DeliveryError::Status(status))
    }
}

/// Send an email through Resend (the BILL-01 path).
async fn deliver_email(mail: &Mail, to: &str, text: &str) -> Result<(), DeliveryError> {
    if mail.api_key.is_none() {
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::UsageWarningEmailUnconfigured,
        );
        return Err(DeliveryError::EmailUnconfigured);
    }
    let url = tracelane_shared::email::RESEND_API_URL;
    crate::ssrf_guard::validate_url(url)
        .await
        .map_err(|e| DeliveryError::Rejected(e.to_string()))?;
    let http = crate::billing::email::http_client();
    tracelane_shared::email::send_plain_text(
        &http,
        url,
        mail.api_key.as_ref(),
        &mail.from,
        to,
        "Tracelane: spend alert",
        text,
    )
    .await
    .map_err(|e| match e {
        tracelane_shared::email::EmailError::Unconfigured => DeliveryError::EmailUnconfigured,
        other => DeliveryError::Unreachable(other.to_string()),
    })
}

/// Open a channel's sealed secret.
fn open_secret(ch: &crate::db::spend_alerts::Sealed) -> Result<SecretString, DeliveryError> {
    let Some(enc) = ch.secret_enc.as_deref() else {
        return Err(DeliveryError::Secret("none stored".into()));
    };
    let Some(mk) = crate::byok::master_key() else {
        return Err(DeliveryError::Secret("no BYOK master key".into()));
    };
    mk.decrypt_with_context(enc, &channel_aad(ch.tenant_id, ch.id))
        .map_err(|_| DeliveryError::Secret("could not be opened".into()))
}

/// Deliver one event to one channel.
///
/// # Errors
/// Any [`DeliveryError`]; the caller retries with back-off.
pub(crate) async fn deliver(
    mail: &Mail,
    ch: &crate::db::spend_alerts::Sealed,
    event_id: uuid::Uuid,
    payload: &Value,
) -> Result<(), DeliveryError> {
    let text = message_text(payload);
    match ch.kind.as_str() {
        "email" => deliver_email(mail, &ch.target, &text).await,
        "slack" => {
            let url = open_secret(ch)?;
            crate::alerts::deliver_alert(url.expose_secret(), &text)
                .await
                .map(|_| ())
                .map_err(|e| match e {
                    crate::alerts::DeliveryError::Rejected(m) => DeliveryError::Rejected(m),
                    crate::alerts::DeliveryError::Unreachable(m) => DeliveryError::Unreachable(m),
                    crate::alerts::DeliveryError::Status { http_status, .. } => {
                        DeliveryError::Status(http_status)
                    }
                })
        }
        "webhook" => {
            let secret = open_secret(ch)?;
            let mut body = payload.clone();
            body["event_id"] = Value::String(event_id.to_string());
            deliver_webhook(&ch.target, &secret, event_id, &body)
                .await
                .map(|_| ())
        }
        other => Err(DeliveryError::Secret(format!(
            "unknown channel kind {other}"
        ))),
    }
}

// ── The background task ──────────────────────────────────────────────────────

/// Spawn the ONE worker: drain crossings into the outbox, deliver due rows. Started at
/// boot when a Postgres control plane exists.
pub(crate) fn spawn(pool: crate::db::DbPool, mail: Mail) {
    let Some(mut rx) = queue().1.lock().ok().and_then(|mut g| g.take()) else {
        return;
    };
    let cfg = crate::controls::config();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(cfg.alert_poll_interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                Some(c) = rx.recv() => {
                    if let Err(e) = crate::db::spend_alerts::enqueue(&pool, c.tenant, &c.dedup_key, &c.payload).await {
                        tracelane_shared::degradation::note(
                            tracelane_shared::degradation::Degradation::SpendAlertDeliveryFailed,
                        );
                        tracing::debug!(error = %format!("{e:#}"), "spend alert outbox insert failed");
                    }
                }
                _ = tick.tick() => deliver_due(&pool, &mail, cfg).await,
            }
        }
    });
}

async fn deliver_due(pool: &crate::db::DbPool, mail: &Mail, cfg: crate::controls::ControlsConfig) {
    let due = match crate::db::spend_alerts::claim_due(pool, 50, LEASE_SECS).await {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(error = %format!("{e:#}"), "spend alert claim failed");
            return;
        }
    };
    for d in due {
        let result = deliver(mail, &d.channel, d.event_id, &d.payload).await;
        let attempts = u32::try_from(d.attempts).unwrap_or(0) + 1;
        let give_up = result.is_err() && attempts >= cfg.alert_max_attempts;
        let retry = cfg
            .alert_backoff_base_secs
            .saturating_mul(1u64 << attempts.min(16));
        if result.is_err() {
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::SpendAlertDeliveryFailed,
            );
        } else {
            tracelane_shared::degradation::resolve(
                tracelane_shared::degradation::Degradation::SpendAlertDeliveryFailed,
            );
        }
        let outcome = result.map_err(|e| e.to_string());
        if let Err(e) = crate::db::spend_alerts::record_outcome(
            pool,
            d.event_id,
            outcome,
            i64::try_from(retry).unwrap_or(i64::MAX),
            give_up,
        )
        .await
        {
            tracing::debug!(error = %format!("{e:#}"), "spend alert outcome write failed");
        }
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::handler_harness::LoopbackBypassGuard;
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn secret() -> SecretString {
        SecretString::from("whsec_test".to_owned())
    }

    #[test]
    fn og24_a_signature_verifies_and_tampering_wrong_keys_and_old_timestamps_do_not() {
        let body = br#"{"threshold":"80%"}"#;
        let now = 1_800_000_000;
        let h = sign(&secret(), now, body);
        assert!(h.starts_with(&format!("t={now},v1=")));
        assert!(verify_signature(&secret(), &h, body, now, 300));
        assert!(
            verify_signature(&secret(), &h, body, now + 300, 300),
            "inside the window"
        );
        assert!(
            !verify_signature(&secret(), &h, body, now + 301, 300),
            "a replay after 300 s"
        );
        assert!(
            !verify_signature(&secret(), &h, br#"{"threshold":"81%"}"#, now, 300),
            "tampered"
        );
        assert!(
            !verify_signature(
                &SecretString::from("whsec_other".to_owned()),
                &h,
                body,
                now,
                300
            ),
            "wrong secret"
        );
        assert!(
            !verify_signature(&secret(), "t=1,v1=zz", body, 1, 300),
            "garbage"
        );
        let s1 = new_signing_secret().expect("rng");
        let s2 = new_signing_secret().expect("rng");
        assert!(s1.expose_secret().starts_with("whsec_"));
        assert_ne!(s1.expose_secret(), s2.expose_secret());
    }

    #[tokio::test]
    async fn og24_a_private_or_metadata_url_is_refused_before_any_packet() {
        for url in [
            "http://127.0.0.1/hook",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.5/hook",
        ] {
            let r =
                deliver_webhook(url, &secret(), uuid::Uuid::new_v4(), &serde_json::json!({})).await;
            assert!(matches!(r, Err(DeliveryError::Rejected(_))), "{url}: {r:?}");
        }
    }

    #[tokio::test]
    async fn og24_a_webhook_delivery_carries_the_three_headers_and_a_verifiable_body() {
        let _b = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header_exists("x-tracelane-signature"))
            .and(header_exists("x-tracelane-timestamp"))
            .and(header_exists("x-tracelane-event-id"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let id = uuid::Uuid::new_v4();
        let body = serde_json::json!({"threshold": "80%", "spent_usd": 8.0});
        let status = deliver_webhook(&format!("{}/hook", server.uri()), &secret(), id, &body)
            .await
            .expect("delivered");
        assert_eq!(status, 204);
        let reqs = server.received_requests().await.expect("log");
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        let sig = r
            .headers
            .get("x-tracelane-signature")
            .unwrap()
            .to_str()
            .unwrap();
        let ts: i64 = r
            .headers
            .get("x-tracelane-timestamp")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            r.headers
                .get("x-tracelane-event-id")
                .unwrap()
                .to_str()
                .unwrap(),
            id.to_string()
        );
        assert!(verify_signature(&secret(), sig, &r.body, ts, 300));
        // A non-2xx is NOT a delivery.
        let failing = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&failing)
            .await;
        assert_eq!(
            deliver_webhook(&failing.uri(), &secret(), id, &body).await,
            Err(DeliveryError::Status(500))
        );
    }

    #[test]
    fn og24_the_message_names_the_numbers_and_nothing_else() {
        let t = message_text(&serde_json::json!({
            "scope": "project", "subject_id": "p-1", "threshold": "80%", "window": "monthly",
            "policy": "project", "spent_usd": 80.0, "budget_usd": 100.0, "mode": "hard"
        }));
        assert_eq!(
            t,
            "Tracelane spend alert — project p-1 reached 80% of its monthly project budget: $80.00 \
             spent of $100.00 (hard mode)."
        );
    }
}
