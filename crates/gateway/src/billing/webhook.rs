//! Polar.sh webhook handler — POST /v1/webhooks/polar.
//!
//! Polar uses the [Standard Webhooks] spec for signing. Every delivery
//! carries three headers:
//!   - `webhook-id`: stable per-event id (UUID).
//!   - `webhook-timestamp`: unix seconds at delivery time.
//!   - `webhook-signature`: `v1,<base64-sig>` (one or more `v1,` entries
//!     during a secret-rotation window).
//!
//! The signed payload is `${webhook_id}.${webhook_timestamp}.${body}`,
//! HMAC-SHA256 with the webhook secret as the key, base64-encoded.
//!
//! Polar's shared webhook secret is `polar_whs_<…>`; the HMAC key is the
//! raw UTF-8 bytes of the ENTIRE secret string (prefix included) — NOT
//! base64-decoded. Polar's own `validateEvent` base64-encodes the secret
//! and the `standardwebhooks` lib base64-decodes it back, so the two
//! transforms cancel to `utf8(secret)`.
//!
//! Pipeline:
//!   1. Verify the signature using the configured webhook secret.
//!   2. Reject events older than 5 minutes (replay protection).
//!   3. Parse the event JSON.
//!   4. Cross-check `data.organization_id` against
//!   5. Dedupe on `(source=polar, webhook-id header)` via Postgres — record
//!      no top-level id; the unique delivery id is the `webhook-id` header.
//!   6. Dispatch on `type` (subscription.{created,updated,canceled,...}).
//!   7. Return 200 OK; 5xx surfaces errors so Polar retries.
//!
//! Configure: set `POLAR_WEBHOOK_SECRET` to the value Polar shows when
//! you create the webhook endpoint (`polar_whs_<…>`). Without it the
//! handler returns 503 — never accepts unsigned events.
//!
//! [Standard Webhooks]: https://www.standardwebhooks.com/

use anyhow::{Context as _, Result, bail};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use ring::hmac;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use std::sync::Arc;

/// Tolerance for the `webhook-timestamp` header, in seconds. Older
/// signed payloads are rejected as replay attempts. 5 minutes is the
/// Standard Webhooks recommended bound.
const TOLERANCE_SECONDS: i64 = 300;

/// Cap on the number of v1 signatures we consider. Bounded to defend
/// against an attacker sending a multi-megabyte signature header
/// (R3 H5 symmetric guard).
const MAX_V1_SIGS: usize = 8;

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// The Polar webhook secret string itself (`polar_whs_<…>`). Polar keys
    /// the HMAC with the raw UTF-8 bytes of this whole string, so the HMAC
    /// key is simply `secret.expose_secret().as_bytes()` at verify time.
    pub secret: SecretString,
}

impl WebhookConfig {
    /// Read + decode the webhook secret from `POLAR_WEBHOOK_SECRET`.
    /// Returns `None` if the env var is unset.
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("POLAR_WEBHOOK_SECRET").ok()?;
        let decoded = decode_secret(&raw).ok()?;
        Some(Self {
            secret: SecretString::from(decoded),
        })
    }
}

/// Derive the HMAC key material from a Polar webhook secret.
///
/// Polar's keying is NOT the vanilla Standard Webhooks convention: the HMAC
/// key is the raw UTF-8 bytes of the *entire* secret string (`polar_whs_<…>`,
/// prefix included) — no prefix strip, no base64 decode. Polar's
/// `validateEvent` does `base64(utf8(secret))` and `standardwebhooks`
/// base64-decodes it back, so the transforms cancel to `utf8(secret)`. We
/// return the (trimmed) secret string itself; the caller keys on its bytes.
/// `.trim()` guards a stray trailing newline in the env var.
fn decode_secret(raw: &str) -> Result<String> {
    Ok(raw.trim().to_string())
}

#[derive(Debug)]
struct ParsedSignature {
    v1_sigs: Vec<String>,
}

fn parse_signature_header(header: &str) -> Result<ParsedSignature> {
    let mut v1: Vec<String> = Vec::new();
    for part in header.split(' ') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((scheme, sig)) = part.split_once(',') else {
            continue;
        };
        if scheme == "v1" {
            if sig.len() > 256 {
                continue;
            }
            v1.push(sig.to_string());
            if v1.len() >= MAX_V1_SIGS {
                break;
            }
        }
    }
    if v1.is_empty() {
        bail!("webhook-signature has no v1 entries");
    }
    Ok(ParsedSignature { v1_sigs: v1 })
}

/// Verify the Standard Webhooks signature.
pub fn verify_signature(
    webhook_id: &str,
    webhook_timestamp: &str,
    signature_header: &str,
    body: &[u8],
    secret_bytes: &[u8],
    now_unix: i64,
) -> Result<()> {
    let timestamp: i64 = webhook_timestamp
        .parse()
        .context("webhook-timestamp not a unix integer")?;
    let age = now_unix - timestamp;
    if age.abs() > TOLERANCE_SECONDS {
        bail!("webhook-timestamp out of tolerance: {age}s");
    }

    let parsed = parse_signature_header(signature_header)?;

    let mut signed =
        Vec::with_capacity(webhook_id.len() + 1 + webhook_timestamp.len() + 1 + body.len());
    signed.extend_from_slice(webhook_id.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(webhook_timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret_bytes);
    let expected = hmac::sign(&key, &signed);
    let expected_b64 = B64.encode(expected.as_ref());

    let matched = parsed
        .v1_sigs
        .iter()
        .any(|s| constant_time_eq(s.as_bytes(), expected_b64.as_bytes()));
    if !matched {
        bail!("webhook-signature v1 entry did not match expected HMAC");
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Polar's Standard Webhooks envelope: `{ type, timestamp, data }`. There is
/// **no top-level `id`** — the unique delivery id is the `webhook-id` header,
/// which the handler uses as the idempotency key. (A required `id` field here
/// would make `serde_json::from_slice` reject every real Polar delivery.)
#[derive(Debug, Deserialize)]
struct PolarEvent {
    #[serde(rename = "type")]
    event_type: String,
    data: serde_json::Value,
}

#[derive(Clone)]
pub struct WebhookState {
    pub config: Arc<WebhookConfig>,
}

pub async fn handler(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let webhook_id = match headers.get("webhook-id").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return (StatusCode::BAD_REQUEST, "missing webhook-id header"),
    };
    let webhook_ts = match headers
        .get("webhook-timestamp")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_owned(),
        None => return (StatusCode::BAD_REQUEST, "missing webhook-timestamp header"),
    };
    let signature = match headers
        .get("webhook-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_owned(),
        None => return (StatusCode::BAD_REQUEST, "missing webhook-signature header"),
    };

    let now_unix = chrono::Utc::now().timestamp();
    // Polar keys the HMAC with the raw UTF-8 bytes of the secret string
    // (see module docs + `decode_secret`).
    let secret_bytes = state.config.secret.expose_secret().as_bytes();
    if let Err(err) = verify_signature(
        &webhook_id,
        &webhook_ts,
        &signature,
        &body,
        secret_bytes,
        now_unix,
    ) {
        tracing::warn!(error = %err, "Polar webhook signature verification failed");
        return (StatusCode::UNAUTHORIZED, "signature verification failed");
    }

    let event: PolarEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(_) => {
            tracing::warn!("Polar webhook body not parseable as event JSON");
            return (StatusCode::BAD_REQUEST, "malformed event JSON");
        }
    };

    tracing::info!(
        event_id = %webhook_id,
        event_type = %event.event_type,
        "Polar webhook received"
    );

    // Mandatory; opt-out for tests only.
    if !is_org_test_bypass_enabled() {
        let expected = match std::env::var("POLAR_EXPECTED_ORGANIZATION_ID") {
            Ok(v) => v,
            Err(_) => {
                tracing::error!("POLAR_EXPECTED_ORGANIZATION_ID unset; refusing webhook event");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "POLAR_EXPECTED_ORGANIZATION_ID unset",
                );
            }
        };
        let actual = extract_organization_id(&event.data);
        if actual.as_deref() != Some(&expected) {
            tracing::warn!(
                event_id = %webhook_id,
                expected = %expected,
                actual = ?actual,
                "Polar event organization_id mismatch — refusing",
            );
            return (StatusCode::UNAUTHORIZED, "organization_id mismatch");
        }
    }

    if let Some(pool) = crate::db::global_pool() {
        match crate::db::webhook_events::already_processed(
            pool,
            crate::db::webhook_events::WebhookSource::Polar,
            &webhook_id,
        )
        .await
        {
            Ok(true) => {
                tracing::info!(event_id = %webhook_id, "Polar webhook replayed — already processed; skipping");
                return (StatusCode::OK, "ok (duplicate)");
            }
            Ok(false) => { /* fall through */ }
            Err(err) => {
                tracing::warn!(error = %err, event_id = %webhook_id, "Polar webhook dedup query failed");
                return (StatusCode::SERVICE_UNAVAILABLE, "dedup unavailable");
            }
        }
    }

    if let Err(err) = dispatch_event(&event).await {
        tracing::warn!(error = %err, event_id = %webhook_id, "Polar webhook dispatch failed");
        return (StatusCode::SERVICE_UNAVAILABLE, "dispatch failed");
    }

    if let Some(pool) = crate::db::global_pool() {
        if let Err(err) = crate::db::webhook_events::try_record_processed(
            pool,
            crate::db::webhook_events::WebhookSource::Polar,
            &webhook_id,
        )
        .await
        {
            tracing::warn!(error = %err, event_id = %webhook_id, "post-dispatch dedup record failed (side effect already applied)");
        }
    }

    (StatusCode::OK, "ok")
}

fn extract_organization_id(data: &serde_json::Value) -> Option<String> {
    // Org-scoped events carry a top-level organization_id.
    if let Some(v) = data.get("organization_id").and_then(|v| v.as_str()) {
        return Some(v.to_string());
    }
    // Subscription/order events do NOT — the org id lives on the nested
    // `product` (Polar's Subscription has no top-level organization_id).
    if let Some(v) = data
        .get("product")
        .and_then(|p| p.get("organization_id"))
        .and_then(|v| v.as_str())
    {
        return Some(v.to_string());
    }
    if let Some(v) = data
        .get("subscription")
        .and_then(|s| s.get("organization_id"))
        .and_then(|v| v.as_str())
    {
        return Some(v.to_string());
    }
    None
}

#[cfg(debug_assertions)]
fn is_org_test_bypass_enabled() -> bool {
    std::env::var("TRACELANE_POLAR_TEST_NO_ORG_CHECK").as_deref() == Ok("1")
}

#[cfg(not(debug_assertions))]
fn is_org_test_bypass_enabled() -> bool {
    false
}

async fn dispatch_event(event: &PolarEvent) -> Result<()> {
    match event.event_type.as_str() {
        "subscription.created"
        | "subscription.updated"
        | "subscription.active"
        | "subscription.canceled"
        | "subscription.revoked"
        | "subscription.uncanceled" => handle_subscription_change(event).await,
        "order.created" | "order.paid" => {
            tracing::info!(event_type = %event.event_type, "Polar order event (no action in V1)");
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Debug, Deserialize)]
struct SubscriptionPayload {
    id: String,
    customer_id: String,
    status: String,
    product: Option<ProductPayload>,
}

#[derive(Debug, Deserialize)]
struct ProductPayload {
    #[serde(default)]
    metadata: std::collections::HashMap<String, serde_json::Value>,
}

async fn handle_subscription_change(event: &PolarEvent) -> Result<()> {
    let sub: SubscriptionPayload = serde_json::from_value(event.data.clone())
        .context("event.data not a subscription shape")?;

    let plan_tier = if matches!(
        event.event_type.as_str(),
        "subscription.canceled" | "subscription.revoked"
    ) || sub.status == "canceled"
        || sub.status == "revoked"
    {
        "free"
    } else {
        sub.product
            .as_ref()
            .and_then(|p| p.metadata.get("lookup_key"))
            .and_then(|v| v.as_str())
            .map(|key| match key {
                "builder_v1" => "builder",
                "team_v1" => "team",
                "business_v1" => "business",
                "enterprise_v1" => "enterprise",
                _ => "free",
            })
            .unwrap_or("free")
    };

    let pool = match crate::db::global_pool() {
        Some(p) => p,
        None => {
            tracing::warn!(
                customer = %sub.customer_id,
                "no Postgres pool — cannot apply subscription change"
            );
            return Ok(());
        }
    };

    let tenant = crate::db::tenants::get_by_polar_customer(pool, &sub.customer_id)
        .await
        .context("get_by_polar_customer failed")?;
    let tenant = match tenant {
        Some(t) => t,
        None => {
            tracing::warn!(customer = %sub.customer_id, "no tenant for polar_customer_id");
            return Ok(());
        }
    };

    let tenant_wrapped = tracelane_shared::TenantId::from_jwt_claim(tenant.tenant_id);
    crate::db::tenants::set_plan_tier(pool, &tenant_wrapped, plan_tier)
        .await
        .context("set_plan_tier failed")?;

    tracing::info!(
        tenant_id = %tenant.tenant_id,
        plan_tier = %plan_tier,
        subscription_id = %sub.id,
        "Polar subscription change applied"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signed(
        webhook_id: &str,
        body: &[u8],
        secret_bytes: &[u8],
        ts: i64,
    ) -> (String, String) {
        let mut signed = Vec::new();
        signed.extend_from_slice(webhook_id.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(ts.to_string().as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret_bytes);
        let h = hmac::sign(&key, &signed);
        let sig_b64 = B64.encode(h.as_ref());
        (ts.to_string(), format!("v1,{sig_b64}"))
    }

    #[test]
    fn verify_accepts_valid_signature() {
        let body = br#"{"id":"evt_1","type":"subscription.created"}"#;
        let secret = b"tracelane-polar-test-secret";
        let webhook_id = "msg_01HABCDE";
        let now = 1_700_000_000_i64;
        let (ts, sig) = make_signed(webhook_id, body, secret, now);
        verify_signature(webhook_id, &ts, &sig, body, secret, now).expect("valid sig");
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let body = b"{}";
        let webhook_id = "msg_01HABCDE";
        let now = 1_700_000_000_i64;
        let (ts, sig) = make_signed(webhook_id, body, b"real_secret", now);
        assert!(verify_signature(webhook_id, &ts, &sig, body, b"wrong_secret", now).is_err());
    }

    #[test]
    fn verify_rejects_replayed_old_signature() {
        let body = b"{}";
        let secret = b"polar-test";
        let webhook_id = "msg_x";
        let signed_at = 1_700_000_000_i64;
        let (ts, sig) = make_signed(webhook_id, body, secret, signed_at);
        let now = signed_at + 600;
        assert!(verify_signature(webhook_id, &ts, &sig, body, secret, now).is_err());
    }

    #[test]
    fn verify_rejects_modified_body() {
        let body_orig = b"{\"plan\":\"team\"}";
        let body_tampered = b"{\"plan\":\"enterprise\"}";
        let secret = b"polar-test";
        let webhook_id = "msg_x";
        let now = 1_700_000_000_i64;
        let (ts, sig) = make_signed(webhook_id, body_orig, secret, now);
        assert!(verify_signature(webhook_id, &ts, &sig, body_tampered, secret, now).is_err());
    }

    #[test]
    fn verify_rejects_modified_webhook_id() {
        // The signed payload includes webhook_id, so substituting the id
        // header invalidates the signature.
        let body = b"{}";
        let secret = b"polar-test";
        let now = 1_700_000_000_i64;
        let (ts, sig) = make_signed("msg_original", body, secret, now);
        assert!(
            verify_signature("msg_attacker_substituted", &ts, &sig, body, secret, now).is_err()
        );
    }

    #[test]
    fn verify_accepts_when_one_of_multiple_v1_matches() {
        let body = b"{}";
        let secret = b"polar-new";
        let webhook_id = "msg_x";
        let now = 1_700_000_000_i64;
        let (ts, real_sig) = make_signed(webhook_id, body, secret, now);
        let header = format!("{real_sig} v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        verify_signature(webhook_id, &ts, &header, body, secret, now).expect("real sig matches");
    }

    #[test]
    fn parse_signature_header_extracts_v1_entries() {
        let p = parse_signature_header("v1,abc v1,def v0,ignored").unwrap();
        assert_eq!(p.v1_sigs, vec!["abc", "def"]);
    }

    #[test]
    fn parse_signature_header_caps_v1_count() {
        let header = (0..32)
            .map(|i| format!("v1,sig{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let p = parse_signature_header(&header).unwrap();
        assert_eq!(p.v1_sigs.len(), MAX_V1_SIGS);
    }

    #[test]
    fn parse_signature_header_rejects_no_v1() {
        assert!(parse_signature_header("v0,abc").is_err());
    }

    #[test]
    fn decode_secret_uses_raw_utf8_key() {
        // Polar keys the HMAC with the raw UTF-8 bytes of the whole secret
        // string (prefix included) — no strip, no base64 decode.
        let raw = "polar_whs_abc123";
        let s = decode_secret(raw).unwrap();
        assert_eq!(s.as_bytes(), raw.as_bytes());
    }

    #[test]
    fn decode_secret_trims_surrounding_whitespace() {
        let s = decode_secret("  polar_whs_abc123\n").unwrap();
        assert_eq!(s.as_bytes(), b"polar_whs_abc123");
    }

    #[test]
    fn decode_secret_matches_polar_sdk_derivation() {
        // Polar SDK: base64Secret = base64(utf8(secret)); standardwebhooks then
        // base64-DECODES it (the value never starts with `whsec_`) → utf8(secret).
        // The effective key is therefore the raw secret bytes; assert parity.
        let raw = "polar_whs_abc123";
        let base64_secret = B64.encode(raw.as_bytes());
        let sdk_key = B64.decode(&base64_secret).unwrap();
        assert_eq!(decode_secret(raw).unwrap().as_bytes(), sdk_key.as_slice());
    }

    #[test]
    fn extract_organization_id_top_level() {
        let data = serde_json::json!({"organization_id": "org_123"});
        assert_eq!(extract_organization_id(&data), Some("org_123".into()));
    }

    #[test]
    fn extract_organization_id_nested() {
        let data = serde_json::json!({"subscription": {"organization_id": "org_456"}});
        assert_eq!(extract_organization_id(&data), Some("org_456".into()));
    }

    #[test]
    fn extract_organization_id_from_product() {
        // Polar subscription/order events: org id lives on the nested product,
        // not at data.organization_id.
        let data = serde_json::json!({"product": {"organization_id": "org_prod"}});
        assert_eq!(extract_organization_id(&data), Some("org_prod".into()));
    }

    #[test]
    fn extract_organization_id_missing() {
        let data = serde_json::json!({"customer_id": "cust_x"});
        assert_eq!(extract_organization_id(&data), None);
    }
}

// ci-cache probe A (no-op comment; cache-key unchanged) — 2026-06-06
