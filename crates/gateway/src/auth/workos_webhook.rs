//! WorkOS webhook handler — POST /v1/webhooks/workos.
//!
//! WorkOS POSTs lifecycle events for users, organizations, and SCIM
//! provisioning. We:
//!   1. Verify `WorkOS-Signature: t=<unix_millis>, v1=<hex>` (HMAC-SHA256
//!      over `<t>.<body>` with `WORKOS_WEBHOOK_SECRET`). Same header shape
//!      as Stripe/Polar, but WorkOS's `t` is a **millisecond** timestamp
//!      (it is compared against `Date.now()` in WorkOS's own SDK), NOT
//!      seconds — the replay-window math therefore runs in milliseconds.
//!   2. Reject events more than 5 minutes out of tolerance in either
//!      direction (replay protection).
//!   3. Parse + dispatch:
//!      - organization.created  -> upsert tenants keyed on workos_org_id
//!      - user.created          -> insert into users (tenant by LOOKUP)
//!      - dsync.user.created    -> insert into users (SCIM provisioned)
//!      - other types           -> log only, ack 200
//!   4. Response semantics: 200 only after dispatch succeeds; a dispatch
//!      or dedup failure returns 503 so WorkOS redelivers (at-least-once,
//!      record-on-success dedupe via `webhook_events` — a replayed
//!      delivery id acks 200 without re-dispatching, so retries cannot
//!      loop side effects).
//!
//!
//! The tenant for an event is resolved by an authoritative Postgres LOOKUP
//! on `tenants.workos_org_id` — NEVER by deriving a UUID from the org id.
//! Prod tenant ids are random (dashboard-onboarded); the old derivation
//! (`tenant_uuid_from_workos_org`) attached users of existing orgs to a
//! tenant UUID that existed in no `tenants` row. Unknown orgs are
//! provisioned on demand via `tenants::create_or_get_by_workos_org`
//! (random UUID, free plan) — idempotent under WorkOS redelivery.
//!
//! Configure: set `WORKOS_WEBHOOK_SECRET` to the value the WorkOS
//! dashboard issues when you create the endpoint. Without it the route
//! stays unmounted (better than 401-ing every request).

use crate::rate_limiter::{BucketState, RateLimitDecision};
use anyhow::{Context as _, Result, anyhow, bail};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use bytes::Bytes;
use ring::hmac;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Replay window for the signature timestamp, in **milliseconds**. WorkOS's
/// `t` is a millisecond Unix timestamp (compared against `Date.now()` in their
/// SDK, default tolerance `18e4` ms), so this bound is in milliseconds too.
/// 5 minutes matches the repo-wide replay tolerance (`security.md`, the Polar
/// billing webhook — which, being Standard Webhooks, keeps its own bound in
/// SECONDS; do not conflate the two units).
const TOLERANCE_MILLIS: i64 = 300_000;

#[derive(Debug, Clone)]
pub struct WorkOsWebhookConfig {
    pub secret: SecretString,
}

impl WorkOsWebhookConfig {
    pub fn from_env() -> Option<Self> {
        std::env::var("WORKOS_WEBHOOK_SECRET").ok().map(|s| Self {
            secret: SecretString::from(s),
        })
    }
}

#[derive(Clone)]
pub struct WorkOsWebhookState {
    pub config: Arc<WorkOsWebhookConfig>,
    /// cloned per-request state so the token bucket is process-wide.
    pub rate_limiter: Arc<WebhookRateLimiter>,
}

///
/// A solo-founder product's real WorkOS signup/webhook rate is far below
/// 1/sec sustained and its bursts are small; 60/min with a 60-event burst
/// absorbs normal onboarding while capping how fast a determined actor can
/// grow `tenants`/`users` rows. Ops override with `WORKOS_WEBHOOK_RATE_PER_MIN`.
const DEFAULT_WEBHOOK_PROVISION_RATE_PER_MIN: u32 = 60;

///
/// Signature verification proves an event was relayed by WorkOS, but not that
/// the control plane may grow unboundedly: WorkOS AuthKit signups are cheap and
/// self-serve, so a determined actor can drive a stream of *genuinely-signed*
/// `organization.created` / `user.created` events, each provisioning a
/// `tenants` / `users` row. This caps authentic provisioning events to
/// `per_minute` globally; a throttled event is not recorded processed, so
/// WorkOS redelivers it once budget frees up (at-least-once → no lost signups).
///
/// **Global (one bucket), not per-IP, by design.** Every provisioning event
/// carries a valid WorkOS signature and therefore originates from WorkOS's own
/// egress IPs, so a single global cap bounds control-plane growth at least as
/// tightly as per-IP would. The server (`server.rs`) runs `axum::serve` without
/// `into_make_service_with_connect_info`, so handlers have no unspoofable peer
/// IP, and a forwarded header is attacker-controlled — global sidesteps both.
/// Only provisioning event types draw from the budget (log-only events cannot
/// grow rows), so a flood of log-only events cannot starve real provisioning.
pub struct WebhookRateLimiter {
    bucket: parking_lot::Mutex<BucketState>,
    capacity: f64,
    refill_per_ms: f64,
}

impl WebhookRateLimiter {
    /// Build a limiter permitting `per_minute` provisioning events (burst =
    /// `per_minute`). A `per_minute` of 0 is clamped to 1 (a zero-capacity
    /// bucket would reject every event, wedging provisioning entirely).
    pub fn new(per_minute: u32) -> Self {
        let capacity = f64::from(per_minute.max(1));
        Self {
            bucket: parking_lot::Mutex::new(BucketState::new(capacity)),
            capacity,
            // capacity tokens per 60_000 ms == `per_minute` per minute.
            refill_per_ms: capacity / 60_000.0,
        }
    }

    /// Read the budget from `WORKOS_WEBHOOK_RATE_PER_MIN`, else the default.
    pub fn from_env() -> Self {
        let per_min = std::env::var("WORKOS_WEBHOOK_RATE_PER_MIN")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_WEBHOOK_PROVISION_RATE_PER_MIN);
        Self::new(per_min)
    }

    /// Try to consume one provisioning token.
    ///
    /// Synchronous and non-blocking: the `parking_lot::Mutex` guard is taken
    /// and dropped entirely within this call, so it is never held across an
    /// `.await` in the async handler (clippy `await_holding_lock` stays clean).
    pub fn check(&self) -> RateLimitDecision {
        let mut b = self.bucket.lock();
        if b.try_consume(self.capacity, self.refill_per_ms) {
            RateLimitDecision::Allow
        } else {
            RateLimitDecision::Throttle {
                retry_after_secs: b.retry_after_secs(self.refill_per_ms).max(1),
            }
        }
    }
}

/// Whether an event type can grow the control plane (provisions a `tenants` or
/// set in lockstep with the provisioning arms of [`dispatch`] (a test pins the
/// correspondence). Log-only events return `false` so a flood of them cannot
/// starve real provisioning.
fn is_provisioning_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "organization.created" | "user.created" | "dsync.user.created"
    )
}

#[derive(Debug)]
struct ParsedSignature {
    timestamp: i64,
    v1_hashes: Vec<String>,
}

/// DoS bound on v1 hash count (A18) — mirrors the Polar webhook cap so a
/// malicious header can't force `MAX * hmac_sha256` work per request.
const MAX_V1_HASHES: usize = 8;

fn parse_signature_header(header: &str) -> Result<ParsedSignature> {
    let mut timestamp: Option<i64> = None;
    let mut v1: Vec<String> = Vec::new();
    for part in header.split(',') {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("malformed WorkOS-Signature segment: {part}"))?;
        match k.trim() {
            "t" => timestamp = Some(v.trim().parse().context("t= not a unix timestamp")?),
            "v1" => {
                if v1.len() >= MAX_V1_HASHES {
                    bail!("WorkOS-Signature has more than {MAX_V1_HASHES} v1 hashes — refusing");
                }
                v1.push(v.trim().to_string());
            }
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or_else(|| anyhow!("WorkOS-Signature missing t="))?;
    if v1.is_empty() {
        bail!("WorkOS-Signature has no v1 hashes");
    }
    Ok(ParsedSignature {
        timestamp,
        v1_hashes: v1,
    })
}

/// Verify a `WorkOS-Signature: t=<unix_millis>, v1=<hex>` header over `body`.
///
/// WorkOS signs `<t>.<body>` with HMAC-SHA256 keyed by the endpoint secret,
/// where `t` is a **millisecond** Unix timestamp. `now_unix_millis` MUST also
/// be milliseconds (`chrono::Utc::now().timestamp_millis()`): feeding a
/// seconds-scale `now` makes the age ≈ -1.78e12 and rejects every live
/// delivery as "outside tolerance" — the bug this contract exists to prevent.
///
/// The HMAC is computed over the timestamp exactly as it arrived on the wire.
/// `parsed.timestamp` is only ever re-serialized (never normalized), so it
/// reproduces the raw `t` byte-for-byte for WorkOS's integer format. Do NOT
/// divide/normalize `parsed.timestamp` — that corrupts the signed payload and
/// breaks every signature. Any unit conversion lives solely in the tolerance
/// comparison below.
///
/// # Errors
/// Fail-closed (security path): a malformed header, a timestamp more than
/// [`TOLERANCE_MILLIS`] out either direction, or an HMAC mismatch all return
/// `Err`, so the caller responds 401 and WorkOS retries the delivery.
pub fn verify_signature(
    header: &str,
    body: &[u8],
    secret: &str,
    now_unix_millis: i64,
) -> Result<()> {
    let parsed = parse_signature_header(header)?;
    // Replay window — `parsed.timestamp` (WorkOS `t`) and `now_unix_millis` are
    // BOTH milliseconds. Mixing units here is exactly the shipped bug. The
    // difference is taken in i128 so a pathological, attacker-controlled `t`
    // (near i64::MIN/MAX, parsed straight off the wire) can never overflow the
    // subtraction or the `abs()` — the fail-closed check stays total in every
    // build profile (debug overflow-checks included).
    let age_millis = i128::from(now_unix_millis) - i128::from(parsed.timestamp);
    if age_millis.abs() > i128::from(TOLERANCE_MILLIS) {
        bail!("signature timestamp outside tolerance: {age_millis}ms");
    }
    // HMAC over `<t>.<body>` — `t` reproduced byte-for-byte from the wire.
    // NEVER normalize `parsed.timestamp` for this; it must equal what WorkOS
    // signed. Unit handling stays confined to the tolerance check above.
    let mut signed = Vec::with_capacity(parsed.timestamp.to_string().len() + 1 + body.len());
    signed.extend_from_slice(parsed.timestamp.to_string().as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let expected_hex = hex::encode(hmac::sign(&key, &signed).as_ref());
    let matched = parsed
        .v1_hashes
        .iter()
        .any(|h| ct_eq(h.as_bytes(), expected_hex.as_bytes()));
    if !matched {
        bail!("WorkOS-Signature v1 hash mismatch");
    }
    Ok(())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Deserialize)]
struct WorkOsEvent {
    id: String,
    event: String,
    data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OrganizationData {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct UserData {
    id: String,
    email: String,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    /// Some events include the org id at the top level, others nest it.
    #[serde(default)]
    organization_id: Option<String>,
}

pub async fn handler(
    State(state): State<WorkOsWebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let signature = match headers
        .get("workos-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_owned(),
        None => return (StatusCode::BAD_REQUEST, "missing WorkOS-Signature header"),
    };
    // WorkOS's `t` is milliseconds — `now` MUST be milliseconds too, or the
    // replay-window check rejects every live delivery (see `verify_signature`).
    let now_millis = chrono::Utc::now().timestamp_millis();
    if let Err(err) = verify_signature(
        &signature,
        &body,
        state.config.secret.expose_secret(),
        now_millis,
    ) {
        tracing::warn!(error = %err, "WorkOS webhook signature verification failed");
        return (StatusCode::UNAUTHORIZED, "signature verification failed");
    }
    let event: WorkOsEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(error = %err, "WorkOS webhook body not parseable");
            return (StatusCode::BAD_REQUEST, "malformed event JSON");
        }
    };
    tracing::info!(event_id = %event.id, event = %event.event, "WorkOS webhook received");

    // See `billing/webhook.rs` for the rationale; same pattern here.
    if let Some(pool) = crate::db::global_pool() {
        match crate::db::webhook_events::already_processed(
            pool,
            crate::db::webhook_events::WebhookSource::WorkOs,
            &event.id,
        )
        .await
        {
            Ok(true) => {
                tracing::info!(event_id = %event.id, "WorkOS webhook replayed — already processed; skipping");
                return (StatusCode::OK, "ok (duplicate)");
            }
            Ok(false) => { /* fall through to dispatch */ }
            Err(err) => {
                tracing::warn!(
                    error = %crate::db::pg_error_chain(&err),
                    event_id = %event.id,
                    "WorkOS webhook dedup query failed"
                );
                return (StatusCode::SERVICE_UNAVAILABLE, "dedup unavailable");
            }
        }
    }

    // bounded rate. Checked here — AFTER signature + dedup, BEFORE dispatch — so
    // only novel, WorkOS-signed events that would actually grow the control
    // plane draw from the budget. A throttled event is NOT recorded processed,
    // so WorkOS redelivers it once budget frees up (at-least-once preserved — no
    // lost signups). Log-only events skip the cap (they can't grow rows).
    if is_provisioning_event(&event.event) {
        if let RateLimitDecision::Throttle { retry_after_secs } = state.rate_limiter.check() {
            tracing::warn!(
                event_id = %event.id,
                event = %event.event,
                retry_after_secs,
                "WorkOS webhook provisioning rate cap hit — deferring (WorkOS will redeliver)"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "provisioning rate limit exceeded — retry shortly",
            );
        }
    }

    if let Err(err) = dispatch(&event).await {
        tracing::warn!(
            error = %crate::db::pg_error_chain(&err),
            event_id = %event.id,
            "WorkOS webhook dispatch failed"
        );
        return (StatusCode::SERVICE_UNAVAILABLE, "dispatch failed");
    }

    if let Some(pool) = crate::db::global_pool() {
        if let Err(err) = crate::db::webhook_events::try_record_processed(
            pool,
            crate::db::webhook_events::WebhookSource::WorkOs,
            &event.id,
        )
        .await
        {
            tracing::warn!(
                error = %crate::db::pg_error_chain(&err),
                event_id = %event.id,
                "post-dispatch dedup record failed (side effect already applied)"
            );
        }
    }
    (StatusCode::OK, "ok")
}

async fn dispatch(event: &WorkOsEvent) -> Result<()> {
    match event.event.as_str() {
        "organization.created" => handle_organization_created(event).await,
        "user.created" | "dsync.user.created" => handle_user_created(event).await,
        _ => Ok(()),
    }
}

///
/// This is NOT a provisioning or resolution path: prod tenant ids are
/// random and the authoritative mapping is `tenants.workos_org_id`. The
/// only remaining caller is `auth::org_tenant_cache`'s debug-build,
/// no-Postgres, no-WorkOS local-dev fallback (plus tests). Production
/// paths (webhook provisioning + the auth bridge) always resolve via
/// Postgres lookup.
pub(crate) fn tenant_uuid_from_workos_org(org_id: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"workos_org:");
    h.update(org_id.as_bytes());
    let bytes = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    Uuid::from_bytes(out)
}

fn user_uuid_from_workos_user(user_id: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"workos_user:");
    h.update(user_id.as_bytes());
    let bytes = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    Uuid::from_bytes(out)
}

#[tracing::instrument(skip(event), fields(event_id = %event.id, event_type = %event.event))]
async fn handle_organization_created(event: &WorkOsEvent) -> Result<()> {
    let org: OrganizationData = serde_json::from_value(event.data.clone())
        .context("organization.created data missing required fields")?;
    let pool = match crate::db::global_pool() {
        Some(p) => p,
        None => {
            tracing::warn!("organization.created: no Postgres pool — skipping");
            return Ok(());
        }
    };
    // (random UUID) already carrying this org id is returned untouched —
    // the event is idempotent instead of failing the UNIQUE constraint.
    match crate::db::tenants::create_or_get_by_workos_org(pool, &org.id, "free")
        .await
        .with_context(|| format!("upsert tenant for workos_org {}", org.id))?
    {
        Some(tenant) => {
            tracing::info!(
                tenant_id = %tenant.tenant_id,
                workos_org = %org.id,
                "tenant resolved/provisioned from WorkOS organization.created"
            );
        }
        None => {
            // Archived (kill-switched) tenant — refuse to resurrect; ack the
            tracing::warn!(
                workos_org = %org.id,
                "organization.created for an ARCHIVED tenant — refused (kill-switch stays cut)"
            );
        }
    }
    Ok(())
}

/// Resolve the tenant for a user event: authoritative LOOKUP on
/// `tenants.workos_org_id` first; only if the org has no tenant yet (webhook
/// enabled after orgs existed, or event ordering) is one provisioned. NEVER
/// derived id matches no `tenants` row → orphaned users / broken tenancy).
///
/// Returns `Ok(None)` when the org's tenant is ARCHIVED (provision refused —
/// kill-switch stays cut.
///
/// Injectable lookup/provision so the resolution contract is unit-testable
/// without Postgres; production passes the `db::tenants` calls.
///
/// # Errors
/// Propagates lookup/provision failures (fail-closed → the webhook returns
/// 503 and WorkOS redelivers).
async fn resolve_tenant_for_user<LFut, PFut>(
    org_id: &str,
    lookup: impl FnOnce(String) -> LFut,
    provision: impl FnOnce(String) -> PFut,
) -> Result<Option<Uuid>>
where
    LFut: std::future::Future<Output = Result<Option<Uuid>>>,
    PFut: std::future::Future<Output = Result<Option<Uuid>>>,
{
    if let Some(existing) = lookup(org_id.to_string()).await? {
        return Ok(Some(existing));
    }
    provision(org_id.to_string()).await
}

/// guarded on `users.tenant_id = EXCLUDED.tenant_id`: a SAME-tenant
/// re-provision converges `workos_user_id`, while a CROSS-tenant email
/// collision is a zero-row no-op. Without the guard, a WorkOS-signable event
/// (an attacker inviting a victim's email into their own org) would silently
/// review F-1 — a cross-tenant user-rebind primitive). Const so the guard is
/// pinned by a test and cannot be dropped silently.
const USER_UPSERT_SQL: &str = "INSERT INTO users (user_id, tenant_id, email, workos_user_id, name)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (email) DO UPDATE
                 SET workos_user_id = EXCLUDED.workos_user_id
                 WHERE users.tenant_id = EXCLUDED.tenant_id";

#[tracing::instrument(skip(event), fields(event_id = %event.id, event_type = %event.event))]
async fn handle_user_created(event: &WorkOsEvent) -> Result<()> {
    let user: UserData = serde_json::from_value(event.data.clone())
        .context("user.created data missing required fields")?;
    let org_id = match user.organization_id.as_deref() {
        Some(o) => o,
        None => {
            tracing::warn!(user_id = %user.id, "user.created without organization_id — skipping");
            return Ok(());
        }
    };
    let user_id = user_uuid_from_workos_user(&user.id);
    let pool = match crate::db::global_pool() {
        Some(p) => p,
        None => {
            tracing::warn!("user.created: no Postgres pool — skipping");
            return Ok(());
        }
    };
    // (free plan, random UUID) so a user event arriving before its
    // organization.created still lands on a real tenant.
    let resolved = resolve_tenant_for_user(
        org_id,
        |org| async move {
            crate::db::tenants::get_tenant_id_by_workos_org(pool, &org)
                .await
                .context("workos_org_id lookup failed")
        },
        |org| async move {
            let t = crate::db::tenants::create_or_get_by_workos_org(pool, &org, "free")
                .await
                .with_context(|| format!("provision tenant for workos_org {org}"))?;
            if let Some(ref t) = t {
                tracing::warn!(
                    tenant_id = %t.tenant_id,
                    workos_org = %org,
                    "user.created for an org with no tenant — provisioned on demand"
                );
            }
            Ok(t.map(|t| t.tenant_id))
        },
    )
    .await?;
    let Some(tenant_id) = resolved else {
        tracing::warn!(
            workos_user = %user.id,
            "user.created for an ARCHIVED tenant — user NOT provisioned (kill-switch stays cut)"
        );
        return Ok(());
    };
    let display_name = match (user.first_name.as_deref(), user.last_name.as_deref()) {
        (Some(f), Some(l)) => format!("{f} {l}"),
        (Some(f), None) => f.to_string(),
        (None, Some(l)) => l.to_string(),
        (None, None) => user.email.clone(),
    };
    // Direct insert — we don't have a users module yet; do it here. See
    // USER_UPSERT_SQL for the tenant-guarded conflict semantics (F-1).
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .execute(
            USER_UPSERT_SQL,
            &[&user_id, &tenant_id, &user.email, &user.id, &display_name],
        )
        .await
        .with_context(|| format!("insert user for workos_user {}", user.id))?;
    if rows == 0 {
        // Guarded conflict: the email already belongs to a DIFFERENT tenant.
        // Refuse the rebind (see USER_UPSERT_SQL) and say so for forensics.
        tracing::warn!(
            workos_user = %user.id,
            tenant_id = %tenant_id,
            "user.created email collision across tenants — rebind REFUSED (F-1)"
        );
        return Ok(());
    }
    tracing::info!(
        user_id = %user_id,
        tenant_id = %tenant_id,
        workos_user = %user.id,
        "user provisioned from WorkOS"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signature(body: &[u8], secret: &str, ts: i64) -> String {
        let mut signed = Vec::new();
        signed.extend_from_slice(ts.to_string().as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(body);
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let h = hmac::sign(&key, &signed);
        format!("t={ts},v1={}", hex::encode(h.as_ref()))
    }

    /// A realistic WorkOS wire timestamp: **milliseconds** since the epoch
    /// (~2026-06). Fixtures MUST use the provider's real wire unit. The
    /// seconds-scale fixtures this module used to carry (`1_700_000_000` with a
    /// `+600` replay offset) were internally consistent in seconds and so never
    /// exercised the ms format — which is exactly why the ms-vs-seconds replay
    /// bug shipped green. Lesson pinned here: fixture timestamps match the
    /// provider's real wire format, not a convenient round number.
    const NOW_MILLIS: i64 = 1_780_000_000_000;

    #[test]
    fn verify_accepts_valid_signature() {
        let body = br#"{"id":"evt_1","event":"user.created","data":{}}"#;
        let secret = "wh_test_secret";
        let header = make_signature(body, secret, NOW_MILLIS);
        verify_signature(&header, body, secret, NOW_MILLIS).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let body = b"{}";
        let header = make_signature(body, "real", NOW_MILLIS);
        assert!(verify_signature(&header, body, "wrong", NOW_MILLIS).is_err());
    }

    #[test]
    fn verify_rejects_replay() {
        let body = b"{}";
        let secret = "s";
        let header = make_signature(body, secret, NOW_MILLIS);
        // 10 minutes later, in MILLISECONDS — exceeds the 5-minute window.
        assert!(verify_signature(&header, body, secret, NOW_MILLIS + 600_000).is_err());
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let secret = "s";
        let header = make_signature(b"a", secret, NOW_MILLIS);
        assert!(verify_signature(&header, b"b", secret, NOW_MILLIS).is_err());
    }

    /// REGRESSION (live WorkOS delivery failed the replay check): WorkOS `t` is
    /// a **millisecond** timestamp. A real delivery arrives a few seconds after
    /// signing, so a millisecond `now` sits just past `t` and the age is a small
    /// positive count of MILLISECONDS — well inside tolerance. Before the fix
    /// the handler fed a SECONDS-scale `now`, making the age ≈ -1.78e12 and
    /// bailing "timestamp too old". The fixture uses the real ms wire format so
    /// this path can never silently pass on mismatched units again.
    #[test]
    fn verify_accepts_real_workos_millisecond_timestamp() {
        let body = br#"{"id":"evt_01H","event":"organization.created","data":{}}"#;
        let secret = "wh_endpoint_secret";
        let signed_at_millis = 1_780_000_123_456_i64; // odd, real-looking ms value
        let header = make_signature(body, secret, signed_at_millis);
        // Delivered 2s later — `now` in MILLISECONDS, as the handler now passes.
        let now_millis = signed_at_millis + 2_000;
        verify_signature(&header, body, secret, now_millis)
            .expect("a real ms-format WorkOS delivery must verify");
    }

    /// Reproduces the production SYMPTOM — a millisecond `t` checked against a
    /// SECONDS-scale `now` (what the buggy handler passed) yields a hugely
    /// negative age and MUST be rejected. Note this pins a *contract*
    /// (`verify_signature`'s `now` is milliseconds, same as `t`) rather than
    /// distinguishing the fix from the bug: `verify_signature` is unit-agnostic,
    /// so this also failed under the old seconds tolerance. The true seam the
    /// bug lived in is covered by `handler_verifies_a_real_time_millisecond_delivery`.
    #[test]
    fn verify_rejects_seconds_scale_now_against_millisecond_timestamp() {
        let body = b"{}";
        let secret = "s";
        let signed_at_millis = 1_780_000_000_000_i64;
        let header = make_signature(body, secret, signed_at_millis);
        // The old handler passed Utc::now().timestamp() — SECONDS.
        let now_seconds = signed_at_millis / 1000;
        let err = verify_signature(&header, body, secret, now_seconds)
            .expect_err("mismatched units (seconds now vs ms t) must be rejected");
        assert!(
            err.to_string().contains("outside tolerance"),
            "expected a replay-window rejection, got: {err}"
        );
    }

    /// The tolerance boundary is measured in MILLISECONDS: 4m59s of skew passes,
    /// 5m01s fails. Guards against a future edit silently reverting the unit.
    #[test]
    fn verify_tolerance_boundary_is_milliseconds() {
        let body = b"{}";
        let secret = "s";
        let header = make_signature(body, secret, NOW_MILLIS);
        verify_signature(&header, body, secret, NOW_MILLIS + 299_000)
            .expect("4m59s skew is within the 5-minute window");
        assert!(
            verify_signature(&header, body, secret, NOW_MILLIS + 301_000).is_err(),
            "5m01s skew must exceed the 5-minute window"
        );
    }

    /// REGRESSION at the HANDLER clock seam — the exact layer the ms-vs-seconds
    /// bug shipped in. The `verify_signature`-level tests are unit-agnostic (the
    /// bug was never IN `verify_signature`), so only driving `handler()` with a
    /// real-time ms signature distinguishes the fix from the outage: a
    /// seconds-scale handler `now` 401s here; a millisecond one verifies.
    /// A log-only event type acks 200 with no Postgres pool (dispatch is a
    /// no-op, and tests never call `set_global_pool`).
    #[tokio::test]
    async fn handler_verifies_a_real_time_millisecond_delivery() {
        use axum::response::IntoResponse as _;
        let secret = "wh_handler_seam_secret";
        let state = WorkOsWebhookState {
            config: Arc::new(WorkOsWebhookConfig {
                secret: SecretString::from(secret.to_string()),
            }),
            rate_limiter: Arc::new(WebhookRateLimiter::new(
                DEFAULT_WEBHOOK_PROVISION_RATE_PER_MIN,
            )),
        };
        // A log-only WorkOS event (dispatch `_ => Ok(())` arm) so a verified
        // delivery acks 200 without touching Postgres.
        let body = br#"{"id":"evt_seam","event":"authentication.succeeded","data":{}}"#.to_vec();
        // Sign with a REAL millisecond `t`, exactly as WorkOS does. `handler`
        // derives its own `now` the same way, so a correct handler verifies it;
        // the age is a sub-millisecond positive value, well inside tolerance.
        let t_millis = chrono::Utc::now().timestamp_millis();
        let header = make_signature(&body, secret, t_millis);
        let mut headers = HeaderMap::new();
        headers.insert("workos-signature", header.parse().unwrap());
        let status = handler(State(state), headers, Bytes::from(body))
            .await
            .into_response()
            .status();
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "a real ms-format delivery must pass verification at the handler \
             seam — a seconds-scale handler `now` is the shipped bug and 401s here"
        );
        assert_eq!(status, StatusCode::OK, "a verified log-only event acks 200");
    }


    fn provisioning_state(secret: &str, per_min: u32) -> WorkOsWebhookState {
        WorkOsWebhookState {
            config: Arc::new(WorkOsWebhookConfig {
                secret: SecretString::from(secret.to_string()),
            }),
            rate_limiter: Arc::new(WebhookRateLimiter::new(per_min)),
        }
    }

    /// Drive `handler()` with one authentic, signed event of `event_type` and
    /// return the HTTP status. No `set_global_pool` in tests, so dispatch is a
    /// no-op and dedup is skipped — a provisioning event's fate is decided by
    async fn post_signed(
        state: &WorkOsWebhookState,
        secret: &str,
        event_type: &str,
        n: usize,
    ) -> StatusCode {
        use axum::response::IntoResponse as _;
        let body = format!(
            r#"{{"id":"evt_{event_type}_{n}","event":"{event_type}","data":{{"id":"org_{n}","name":"n","email":"u{n}@e.test","organization_id":"org_{n}"}}}}"#
        )
        .into_bytes();
        let t = chrono::Utc::now().timestamp_millis();
        let header = make_signature(&body, secret, t);
        let mut headers = HeaderMap::new();
        headers.insert("workos-signature", header.parse().unwrap());
        handler(State(state.clone()), headers, Bytes::from(body))
            .await
            .into_response()
            .status()
    }

    #[test]
    fn webhook_rate_limiter_allows_burst_then_throttles() {
        let rl = WebhookRateLimiter::new(3); // 3/min, burst 3
        for _ in 0..3 {
            assert!(matches!(rl.check(), RateLimitDecision::Allow));
        }
        match rl.check() {
            RateLimitDecision::Throttle { retry_after_secs } => assert!(retry_after_secs >= 1),
            RateLimitDecision::Allow => panic!("4th event past a 3/min cap must throttle"),
        }
    }

    #[test]
    fn webhook_rate_limiter_zero_per_min_is_clamped_not_wedged() {
        // A 0 budget must NOT reject every event (that would wedge provisioning);
        // it clamps to a 1-token bucket.
        let rl = WebhookRateLimiter::new(0);
        assert!(matches!(rl.check(), RateLimitDecision::Allow));
        assert!(matches!(rl.check(), RateLimitDecision::Throttle { .. }));
    }

    /// The provisioning-event set MUST match `dispatch`'s provisioning arms —
    #[test]
    fn is_provisioning_event_matches_dispatch_arms() {
        assert!(is_provisioning_event("organization.created"));
        assert!(is_provisioning_event("user.created"));
        assert!(is_provisioning_event("dsync.user.created"));
        assert!(!is_provisioning_event("authentication.succeeded"));
        assert!(!is_provisioning_event("organization.updated"));
        assert!(!is_provisioning_event("user.updated"));
    }

    /// throttled at the handler with 429, so the control plane cannot grow
    /// unboundedly from cheap signed events.
    #[tokio::test]
    async fn handler_throttles_provisioning_events_past_cap() {
        let secret = "b078-cap-fake"; // clearly-fake test key (testing.md)
        let state = provisioning_state(secret, 2); // 2 provisions/min, burst 2

        // Burst of 2 authentic provisioning events consumes the budget (200 — no
        // pool, so dispatch is a no-op, but the event is accepted/handled).
        assert_eq!(
            post_signed(&state, secret, "organization.created", 0).await,
            StatusCode::OK
        );
        assert_eq!(
            post_signed(&state, secret, "organization.created", 1).await,
            StatusCode::OK
        );
        // The 3rd authentic provisioning event exceeds the per-minute cap → 429.
        assert_eq!(
            post_signed(&state, secret, "organization.created", 2).await,
            StatusCode::TOO_MANY_REQUESTS,
            "provisioning events past the per-minute cap must 429"
        );
    }

    /// `user.created` is throttled once an `organization.created` drained it.
    #[tokio::test]
    async fn handler_provisioning_budget_is_shared_across_event_types() {
        let secret = "b078-shared-fake"; // clearly-fake test key (testing.md)
        let state = provisioning_state(secret, 1); // a single provision/min

        assert_eq!(
            post_signed(&state, secret, "organization.created", 0).await,
            StatusCode::OK
        );
        assert_eq!(
            post_signed(&state, secret, "user.created", 1).await,
            StatusCode::TOO_MANY_REQUESTS,
            "a user.created must draw from the same drained budget as org.created"
        );
    }

    /// flood of them cannot starve real tenant/user provisioning.
    #[tokio::test]
    async fn handler_log_only_events_bypass_the_provisioning_cap() {
        let secret = "b078-logonly-fake"; // clearly-fake test key (testing.md)
        let state = provisioning_state(secret, 1); // cap of 1 provision/min

        // Far more than the cap — all 200; log-only events never consume budget.
        for n in 0..5 {
            assert_eq!(
                post_signed(&state, secret, "authentication.succeeded", n).await,
                StatusCode::OK,
                "log-only events must never be rate-limited"
            );
        }
        // ...and the untouched provisioning budget is still available afterwards.
        assert_eq!(
            post_signed(&state, secret, "organization.created", 99).await,
            StatusCode::OK,
            "log-only floods must leave the provisioning budget intact"
        );
    }

    /// limiter, so it can neither grow rows nor consume the provisioning budget.
    #[tokio::test]
    async fn handler_bad_signature_does_not_consume_provisioning_budget() {
        use axum::response::IntoResponse as _;
        let secret = "b078-badsig-fake"; // clearly-fake test key (testing.md)
        let state = provisioning_state(secret, 1); // a single provision/min

        // 10 forged-signature provisioning attempts — each 401, none costs budget.
        for n in 0..10 {
            let body = format!(
                r#"{{"id":"evt_forged_{n}","event":"organization.created","data":{{"id":"org_{n}","name":"n"}}}}"#
            )
            .into_bytes();
            let header =
                make_signature(&body, "WRONG_SECRET", chrono::Utc::now().timestamp_millis());
            let mut headers = HeaderMap::new();
            headers.insert("workos-signature", header.parse().unwrap());
            let status = handler(State(state.clone()), headers, Bytes::from(body))
                .await
                .into_response()
                .status();
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // The single provisioning token is still there for a genuine event.
        assert_eq!(
            post_signed(&state, secret, "organization.created", 0).await,
            StatusCode::OK,
            "forged-signature floods must not drain the provisioning budget"
        );
    }

    #[test]
    fn tenant_uuid_is_deterministic() {
        let a = tenant_uuid_from_workos_org("org_abc123");
        let b = tenant_uuid_from_workos_org("org_abc123");
        assert_eq!(a, b);
        let c = tenant_uuid_from_workos_org("org_other");
        assert_ne!(a, c);
    }

    #[test]
    fn user_uuid_is_deterministic_and_distinct_from_tenant() {
        let u = user_uuid_from_workos_user("user_xyz");
        let t = tenant_uuid_from_workos_org("user_xyz");
        // Different prefix => different hash => different UUID
        assert_ne!(u, t);
    }

    #[test]
    fn parse_signature_extracts_t_and_v1() {
        let p = parse_signature_header("t=999,v1=ab,v1=cd").unwrap();
        assert_eq!(p.timestamp, 999);
        assert_eq!(p.v1_hashes, vec!["ab", "cd"]);
    }

    #[test]
    fn parse_signature_rejects_missing_v1() {
        assert!(parse_signature_header("t=1").is_err());
    }

    #[test]
    fn parse_signature_rejects_more_than_max_v1_hashes() {
        // 9 v1= entries exceeds MAX_V1_HASHES (= 8); reject for DoS bound (A18).
        let mut h = String::from("t=1");
        for _ in 0..9 {
            h.push_str(",v1=ab");
        }
        let err = parse_signature_header(&h).unwrap_err().to_string();
        assert!(err.contains("more than 8 v1 hashes"), "got: {err}");
    }


    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    /// the existing tenant UUID (random, dashboard-style — deliberately NOT
    /// equal to the old derivation), and must not provision anything.
    #[test]
    fn user_on_existing_org_resolves_to_the_existing_tenant_uuid() {
        rt().block_on(async {
            let org = "org_existing_dashboard_tenant";
            // A prod-style random tenant id — the derivation CANNOT produce it.
            let existing = Uuid::new_v4();
            assert_ne!(
                existing,
                tenant_uuid_from_workos_org(org),
                "test premise: the real tenant id differs from the derived one"
            );

            let provisioned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = provisioned.clone();
            let resolved = resolve_tenant_for_user(
                org,
                |_org| async move { Ok(Some(existing)) },
                |_org| async move {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(Some(Uuid::new_v4()))
                },
            )
            .await
            .expect("lookup path resolves")
            .expect("existing org must resolve Some");

            assert_eq!(resolved, existing, "must be the LOOKED-UP tenant id");
            assert_ne!(
                resolved,
                tenant_uuid_from_workos_org(org),
                "must NOT be the derived id (the derived-id split-brain)"
            );
            assert!(
                !provisioned.load(std::sync::atomic::Ordering::SeqCst),
                "an existing org must not trigger provisioning"
            );
        });
    }

    #[test]
    fn user_on_unknown_org_provisions_on_demand() {
        rt().block_on(async {
            let fresh = Uuid::new_v4();
            let resolved = resolve_tenant_for_user(
                "org_never_seen",
                |_org| async move { Ok(None) },
                |_org| async move { Ok(Some(fresh)) },
            )
            .await
            .expect("provision path resolves");
            assert_eq!(resolved, Some(fresh));
        });
    }

    /// the resolver returns Ok(None) ("ack, no side effects"), never an id.
    #[test]
    fn user_on_archived_org_is_refused_not_provisioned() {
        rt().block_on(async {
            let resolved = resolve_tenant_for_user(
                "org_archived",
                |_org| async move { Ok(None) }, // active lookup filters archived
                |_org| async move { Ok(None) }, // guarded upsert yields no row
            )
            .await
            .expect("refusal is not an error (ack path)");
            assert_eq!(
                resolved, None,
                "archived org must resolve to None (kill-switch stays cut)"
            );
        });
    }

    /// cross-tenant email-collision attack (attacker invites a victim's email
    /// into their own WorkOS org) is only refused while the DO UPDATE arm is
    /// tenant-guarded and does NOT rewrite tenant_id. SQL semantics run only
    /// against real Postgres, so this pins the statement shape the security
    /// review approved — dropping the guard fails this test.
    #[test]
    fn user_upsert_sql_refuses_cross_tenant_rebind() {
        assert!(
            USER_UPSERT_SQL.contains("WHERE users.tenant_id = EXCLUDED.tenant_id"),
            "the DO UPDATE arm must be guarded on same-tenant"
        );
        let update_arm = USER_UPSERT_SQL
            .split("DO UPDATE")
            .nth(1)
            .expect("upsert has a DO UPDATE arm");
        assert!(
            !update_arm.contains("tenant_id = EXCLUDED.tenant_id")
                || update_arm.contains("WHERE users.tenant_id = EXCLUDED.tenant_id"),
            "DO UPDATE must never SET tenant_id (cross-tenant rebind primitive)"
        );
        assert!(
            !update_arm
                .split("WHERE")
                .next()
                .unwrap_or("")
                .contains("SET tenant_id"),
            "SET clause must not touch tenant_id"
        );
    }

    #[test]
    fn user_resolution_fails_closed_on_lookup_error() {
        rt().block_on(async {
            // A Postgres error must propagate (→ 503 → WorkOS redelivers),
            // never fall through to provisioning or derivation.
            let provisioned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = provisioned.clone();
            let err = resolve_tenant_for_user(
                "org_pg_down",
                |_org| async move { Err(anyhow!("simulated pg outage")) },
                |_org| async move {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(Some(Uuid::new_v4()))
                },
            )
            .await
            .expect_err("lookup error must fail closed");
            assert!(err.to_string().contains("simulated pg outage"));
            assert!(
                !provisioned.load(std::sync::atomic::Ordering::SeqCst),
                "a lookup ERROR must not be treated as org-not-found"
            );
        });
    }
}
