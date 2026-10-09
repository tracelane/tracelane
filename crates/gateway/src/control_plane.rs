//! The admin plane's ONE gate (`OG-34` / `OG-35` / `OG-36`).
//!
//! [`require_control`] is what every route in
//! [`crate::auth::capability::CONTROL_ROUTES`] calls after authenticating. In order:
//!
//! 1. **the capability** — [`Claims::can`] against the role × capability matrix
//!    (OG-34), 403 `role_forbidden` naming the least role that holds it;
//! 2. **the admin IP allowlist** — the workspace's CIDRs (OG-36), checked against
//!    the client address the gateway PROVED: the dashboard's signed attestation
//!    ([`attest`]) or B-594's trusted-proxy derivation
//!    (`preauth_limiter::client_ip`, carried per request and read by
//!    `db::api_keys::current_client_ip`), never a header a client can write;
//! 3. **SSO-required** — a WorkOS session whose authentication method, resolved
//!    from its `sid` through the WorkOS sessions API ([`sso`]), is not `sso` is
//!    refused (OG-36);
//! 4. the [`ControlActor`] the route hands to its store, which records the change
//!    in the change's own transaction (OG-35, `db::control_audit`).
//!
//! **Fail-CLOSED throughout.** An unreadable policy, an address that cannot be
//! proven while an allowlist exists, or an SSO lookup that cannot complete all
//! REFUSE — a security path never treats "could not check" as "allowed" (§10).
//! Inference routes never call this: the allowlist is an admin-plane control.
//!
//! The routes this module mounts itself: `GET`/`PUT /v1/security/admin-access`
//! (OG-36) and `GET`/`POST /v1/audit/control-changes` (OG-35).

use std::net::IpAddr;
use std::sync::OnceLock;

use axum::{
    Json, Router,
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracelane_shared::TenantId;

use crate::auth::Claims;
use crate::auth::capability::{Capability, web_action_capability};
use crate::db::DbPool;
use crate::db::admin_security::AdminAccess;
use crate::db::control_audit::{self, Actor, Change, ListQuery, USER_AGENT_MAX};
use crate::providers::translation_policy::Cidr;

// ── Reference table ────────────────────────────────────────────────────────────

/// `control_policy.v1.json` — the caps and windows this module uses (CLAUDE.md §23).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ControlPolicy {
    pub admin_access: AdminAccessPolicy,
    pub control_audit: ControlAuditPolicy,
    pub rate_limit: ControlRatePolicy,
}

/// rev5 M7 / rev6 N1: per-minute caps on the admin plane. `control_routes_per_minute`,
/// `web_control_changes_per_minute` and `incident_controls_per_minute` are per
/// (workspace, PRINCIPAL) — one caller draining theirs never 429s another;
/// `channel_tests_per_minute` is per workspace (it bounds outbound deliveries).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ControlRatePolicy {
    pub control_routes_per_minute: u32,
    pub web_control_changes_per_minute: u32,
    /// rev5 L5.
    pub channel_tests_per_minute: u32,
    /// rev6 N1: the incident controls' OWN bucket (pause, resume, blocks, revoke-all,
    /// single-key revoke, member removal) — never the shared one.
    pub incident_controls_per_minute: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AdminAccessPolicy {
    pub max_ip_allowlist_entries: usize,
    pub client_ip_attestation_max_skew_secs: i64,
    pub sso_session_cache_ttl_secs: u64,
    pub sso_session_cache_max_entries: u64,
    pub sso_lookup_timeout_ms: u64,
    pub sso_lookup_max_pages: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ControlAuditPolicy {
    pub page_default: i64,
    pub page_max: i64,
    pub change_json_max_bytes: usize,
    /// rev5 M7: the whole web-recorded change (before + after), serialised.
    pub web_change_max_bytes: usize,
}

impl ControlPolicy {
    /// Used only if the shipped JSON does not parse — which
    /// `tests::the_shipped_policy_parses_and_equals_the_fallback` makes unreachable in
    /// a tested build. Equal to the JSON, so a typo neither opens nor closes anything.
    #[must_use]
    pub fn fallback() -> Self {
        Self {
            admin_access: AdminAccessPolicy {
                max_ip_allowlist_entries: 64,
                client_ip_attestation_max_skew_secs: 60,
                sso_session_cache_ttl_secs: 900,
                sso_session_cache_max_entries: 10_000,
                sso_lookup_timeout_ms: 5_000,
                sso_lookup_max_pages: 5,
            },
            control_audit: ControlAuditPolicy {
                page_default: 100,
                page_max: 500,
                change_json_max_bytes: 16_384,
                web_change_max_bytes: 16_384,
            },
            rate_limit: ControlRatePolicy {
                control_routes_per_minute: 120,
                web_control_changes_per_minute: 30,
                channel_tests_per_minute: 6,
                incident_controls_per_minute: 60,
            },
        }
    }
}

const POLICY_JSON: &str = include_str!("../control_policy.v1.json");

/// The parsed reference table (once).
pub fn policy() -> &'static ControlPolicy {
    static P: OnceLock<ControlPolicy> = OnceLock::new();
    P.get_or_init(|| {
        serde_json::from_str(POLICY_JSON).unwrap_or_else(|e| {
            tracing::error!(error = %e, "control_policy.v1.json does not parse — using the documented fallback");
            ControlPolicy::fallback()
        })
    })
}

// ── Refusals ───────────────────────────────────────────────────────────────────

/// A refusal from the admin-plane gate: a status and a JSON body. Routes with a
/// `Response` error type return it as-is; routes with `(StatusCode, String)` use
/// [`ControlRefusal::into_pair`].
#[derive(Debug)]
pub struct ControlRefusal {
    pub status: StatusCode,
    pub body: String,
    /// `Retry-After` seconds (rev5 M7's 429); rendered as the header by `IntoResponse`.
    pub retry_after_secs: Option<u32>,
}

impl ControlRefusal {
    fn new(status: StatusCode, body: &Value) -> Self {
        Self {
            status,
            body: body.to_string(),
            retry_after_secs: None,
        }
    }

    /// rev5 M7: `429 control_rate_limited` + `Retry-After`.
    fn rate_limited(retry_after_secs: u32, what: &str) -> Self {
        Self {
            retry_after_secs: Some(retry_after_secs),
            ..Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                &json!({
                    "error": "control_rate_limited",
                    "message": format!(
                        "this workspace is making {what} faster than the admin plane allows — \
                         retry in {retry_after_secs}s"
                    ),
                    "retry_after_secs": retry_after_secs,
                }),
            )
        }
    }

    /// For routes whose error type is `(StatusCode, String)`.
    #[must_use]
    pub fn into_pair(self) -> (StatusCode, String) {
        (self.status, self.body)
    }

    fn role_forbidden(cap: Capability) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            &json!({
                "error": "role_forbidden",
                "required_role": cap.least_role(),
                "capability": cap.slug(),
                "upgrade_url": null,
            }),
        )
    }

    fn unavailable(code: &str, message: &str) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": code, "message": message}),
        )
    }
}

impl IntoResponse for ControlRefusal {
    fn into_response(self) -> Response {
        let mut resp = (
            self.status,
            [(header::CONTENT_TYPE, "application/json")],
            self.body,
        )
            .into_response();
        if let Some(s) = self.retry_after_secs {
            crate::admission::insert_retry_after(&mut resp, s);
        }
        resp
    }
}

// ── rev5 M7 / rev6 N1: the admin-plane rate limit ─────────────────────────────

/// Which admin-plane bucket a request is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlBucket {
    /// Every route that runs [`require_control`] with a plain capability — per
    /// (workspace, principal).
    Routes,
    /// `POST /v1/audit/control-changes`, in addition (its rows are undeletable) — per
    /// (workspace, principal).
    WebChanges,
    /// rev5 L5: `POST /v1/controls/alert-channels/{id}/test`, in addition (an outbound
    /// delivery per call) — per WORKSPACE: it bounds deliveries, not a principal.
    ChannelTests,
    /// rev6 N1: the incident controls ([`incident`]) INSTEAD of `Routes` — per
    /// (workspace, principal), with its own generous cap, so an owner mid-incident is
    /// never refused because anyone (themselves included) spent the shared bucket.
    Incident,
    /// rev6 N1: refusals by the allowlist / SSO-required, for their log line only — per
    /// (workspace, principal). Never refuses a request; past it the line is skipped.
    RefusalLog,
}

/// What [`require_control`] checks: the capability, and which bucket an admitted call
/// is charged to. A plain [`Capability`] converts into the shared bucket; [`incident`]
/// marks an incident control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlGate {
    cap: Capability,
    incident: bool,
}

impl From<Capability> for ControlGate {
    fn from(cap: Capability) -> Self {
        Self {
            cap,
            incident: false,
        }
    }
}

/// rev6 N1: `cap`, charged to the INCIDENT bucket instead of the shared one. Only the
/// controls an owner reaches for mid-incident use it: pause, resume, blocks,
/// revoke-all, single-key revoke, and member removal (its audit record).
#[must_use]
pub const fn incident(cap: Capability) -> ControlGate {
    ControlGate {
        cap,
        incident: true,
    }
}

/// The dashboard actions recorded through `POST /v1/audit/control-changes` that are
/// incident controls (rev6 N1): removing a member must work while anyone else is
/// hammering the admin plane.
const INCIDENT_WEB_ACTIONS: &[&str] = &["member.remove", "member.remove.failed"];

/// rev5 L5: charge the channel-test bucket for `tenant`.
///
/// # Errors
/// `429 control_rate_limited` with `Retry-After`.
pub(crate) fn charge_channel_test(tenant: &TenantId) -> Result<(), ControlRefusal> {
    charge_control_rate(tenant, None, ControlBucket::ChannelTests)
}

/// Charge `bucket` for `tenant` — and, when `principal` is given, for that principal
/// alone within it (`Claims::sub`: the user id for a session, `apikey:<id>` for a key).
/// The limiter is the gateway's token bucket (`rate_limiter::RateLimiter`), one
/// process-wide instance per bucket; the per-minute caps are the reference table's
/// `rate_limit` block.
///
/// # Errors
/// `429 control_rate_limited` with `Retry-After` when the bucket is empty. Fail-CLOSED
/// on nothing else: the limiter is in-process and cannot be "unavailable".
fn charge_control_rate(
    tenant: &TenantId,
    principal: Option<&str>,
    bucket: ControlBucket,
) -> Result<(), ControlRefusal> {
    static ROUTES: OnceLock<crate::rate_limiter::RateLimiter> = OnceLock::new();
    static WEB: OnceLock<crate::rate_limiter::RateLimiter> = OnceLock::new();
    static TESTS: OnceLock<crate::rate_limiter::RateLimiter> = OnceLock::new();
    static INCIDENT: OnceLock<crate::rate_limiter::RateLimiter> = OnceLock::new();
    static REFUSALS: OnceLock<crate::rate_limiter::RateLimiter> = OnceLock::new();
    #[cfg(not(test))]
    let rpm = {
        let caps = &policy().rate_limit;
        (
            caps.control_routes_per_minute,
            caps.web_control_changes_per_minute,
            caps.channel_tests_per_minute,
            caps.incident_controls_per_minute,
        )
    };
    // See `test_overrides::rate`: a test build pins its own numbers, and an un-pinned
    // test build is not limited.
    #[cfg(test)]
    let Some(rpm) = test_overrides::rate() else {
        return Ok(());
    };
    let (limiter, per_minute, what) = match bucket {
        ControlBucket::Routes => (&ROUTES, rpm.0, "admin requests"),
        ControlBucket::WebChanges => (&WEB, rpm.1, "dashboard control-change records"),
        ControlBucket::ChannelTests => (&TESTS, rpm.2, "alert-channel test deliveries"),
        ControlBucket::Incident => (&INCIDENT, rpm.3, "incident-control requests"),
        ControlBucket::RefusalLog => (&REFUSALS, rpm.0, "refused admin requests"),
    };
    let limiter = limiter.get_or_init(crate::rate_limiter::RateLimiter::new);
    let decision = match principal {
        // The principal's bucket ONLY — no workspace-wide bucket beside it, so nobody
        // else's calls can empty it (rev6 N1).
        Some(p) => limiter.check_scoped(tenant, None, Some(p), Some(per_minute)),
        None => limiter.check(tenant, Some(per_minute)),
    };
    match decision {
        crate::rate_limiter::RateLimitDecision::Allow => Ok(()),
        crate::rate_limiter::RateLimitDecision::Throttle { retry_after_secs } => {
            Err(ControlRefusal::rate_limited(retry_after_secs, what))
        }
    }
}

/// rev6 N1: is this refusal's log line inside the principal's refusal budget? A
/// refused call is charged no admitted bucket (so an attacker outside the allowlist
/// cannot drain the real principal's), so the line needs its own bound.
fn refusal_logged(claims: &Claims) -> bool {
    charge_control_rate(
        &claims.tenant_id,
        Some(&claims.sub),
        ControlBucket::RefusalLog,
    )
    .is_ok()
}

// ── The gate ───────────────────────────────────────────────────────────────────

/// What [`require_control`] proved about the caller: the tenant (from the
/// validated claim, never a body) and the actor every audit row carries.
#[derive(Debug, Clone)]
pub struct ControlActor {
    pub tenant_id: TenantId,
    pub audit: Actor,
    /// The workspace policy the request was admitted under.
    pub access: AdminAccess,
    /// The client address the allowlist was checked against, and how it was proven.
    pub client_ip: Option<IpAddr>,
    pub client_ip_attested: bool,
}

#[cfg(test)]
impl ControlActor {
    /// A gate-passed actor for store tests (no request behind it).
    pub(crate) fn for_test(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            audit: Actor::system("test"),
            access: AdminAccess::default(),
            client_ip: None,
            client_ip_attested: false,
        }
    }
}

/// The admin plane's gate (module doc). Call it AFTER authenticating, on every
/// route in `CONTROL_ROUTES` — `scripts/ci/check-route-auth.py` refuses a listed
/// handler that never reaches it.
///
/// # Errors
/// Fail-CLOSED (a security path): 403 when the role lacks `cap`, the address is
/// outside (or cannot be proven against) a configured allowlist, or SSO is
/// required and the session is not SSO; 503 when the workspace policy cannot be
/// read or the SSO lookup cannot complete. Never "allowed because unknown".
/// 429 `control_rate_limited` when THIS principal's bucket is empty (rev6 N1: per
/// (workspace, principal), charged only once the allowlist and SSO-required admitted
/// the call; an [`incident`] gate draws on its own bucket).
pub async fn require_control(
    claims: &Claims,
    gate: impl Into<ControlGate>,
    headers: &HeaderMap,
) -> Result<ControlActor, ControlRefusal> {
    let gate = gate.into();
    let cap = gate.cap;
    if !claims.can(cap) {
        return Err(ControlRefusal::role_forbidden(cap));
    }
    let access = load_access(&claims.tenant_id).await?;
    let (client_ip, client_ip_attested) = client_ip(headers);

    if !access.admin_ip_allowlist.is_empty() {
        let blocks: Option<Vec<Cidr>> = access
            .admin_ip_allowlist
            .iter()
            .map(|c| Cidr::parse(c))
            .collect();
        let Some(blocks) = blocks else {
            tracing::error!(tenant_id = %claims.tenant_id, "admin IP allowlist holds a non-CIDR entry — refusing control routes");
            return Err(ControlRefusal::unavailable(
                "control_settings_invalid",
                "this workspace's admin IP allowlist could not be read — contact support",
            ));
        };
        let allowed = client_ip.is_some_and(|ip| blocks.iter().any(|b| b.contains(ip)));
        if !allowed {
            // rev5 M4: the checked address is logged here, never echoed in the body. Behind
            // the dashboard, a missing attestation makes it the shared Cloudflare Workers
            // egress IP, and showing it invited an owner to allowlist an address every
            // Worker on the internet shares. The line is bounded per principal by the
            // refusal-log bucket (rev6 N1: a refused call charges no admitted bucket).
            if refusal_logged(claims) {
                tracing::warn!(
                    tenant_id = %claims.tenant_id,
                    client_ip = ?client_ip,
                    attested = client_ip_attested,
                    "admin action refused: address not on the workspace's admin IP allowlist"
                );
            }
            return Err(ControlRefusal::new(
                StatusCode::FORBIDDEN,
                &json!({
                    "error": "admin_ip_not_allowed",
                    "message": "this workspace restricts admin actions to an IP allowlist, and this request's address is not on it",
                }),
            ));
        }
    }

    if access.sso_required && matches!(claims.auth_method, crate::auth::AuthMethod::JwtBearer) {
        match sso::session_is_sso(claims, headers).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(ControlRefusal::new(
                    StatusCode::FORBIDDEN,
                    &json!({
                        "error": "sso_required",
                        "message": "this workspace requires single sign-on for admin actions — sign in through your identity provider and retry",
                    }),
                ));
            }
            Err(e) => {
                if refusal_logged(claims) {
                    tracing::warn!(tenant_id = %claims.tenant_id, error = %e, "SSO-required: session lookup failed — refusing");
                }
                return Err(ControlRefusal::unavailable(
                    "sso_unverifiable",
                    "this workspace requires single sign-on for admin actions, and the session could not be verified — retry",
                ));
            }
        }
    }

    // rev6 N1: charged per (workspace, principal) and only NOW — after the allowlist and
    // SSO-required admitted the call — so neither another principal nor a stolen
    // credential used from outside the allowlist can spend this caller's allowance. The
    // incident controls draw on their own bucket, never the shared one.
    charge_control_rate(
        &claims.tenant_id,
        Some(&claims.sub),
        if gate.incident {
            ControlBucket::Incident
        } else {
            ControlBucket::Routes
        },
    )?;

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|ua| ua.chars().take(USER_AGENT_MAX).collect::<String>());
    Ok(ControlActor {
        tenant_id: claims.tenant_id.clone(),
        audit: Actor {
            sub: claims.sub.clone(),
            role: claims.role_label(),
            auth_method: claims.auth_method_label(),
            request_id: uuid::Uuid::new_v4().to_string(),
            ip: client_ip,
            user_agent,
        },
        access,
        client_ip,
        client_ip_attested,
    })
}

/// The workspace's admin-plane policy. No control plane (self-host, tests without
/// a pool) = no policy: there is nowhere one could have been set.
async fn load_access(tenant: &TenantId) -> Result<AdminAccess, ControlRefusal> {
    #[cfg(test)]
    if let Some(over) = test_overrides::access() {
        return over.map_err(|()| {
            ControlRefusal::unavailable(
                "control_settings_unavailable",
                "the workspace's admin access policy could not be read — retry",
            )
        });
    }
    let Some(pool) = crate::db::global_pool() else {
        return Ok(AdminAccess::default());
    };
    crate::db::admin_security::get(pool, tenant)
        .await
        .map_err(|e| {
            tracing::warn!(tenant_id = %tenant, error = %e, "admin access policy unreadable — refusing the control request");
            ControlRefusal::unavailable(
                "control_settings_unavailable",
                "the workspace's admin access policy could not be read — retry",
            )
        })
}

/// The client address the allowlist is checked against, and whether it came from
/// the dashboard's signed attestation. Attestation first (the dashboard's Worker is
/// the hop that saw the browser); else the ONE trusted-proxy derivation (B-594).
#[must_use]
pub fn client_ip(headers: &HeaderMap) -> (Option<IpAddr>, bool) {
    if let Some(ip) = attest::verified(headers, Utc::now().timestamp()) {
        return (Some(ip), true);
    }
    (crate::db::api_keys::current_client_ip(), false)
}

// ── Dashboard client-IP attestation ────────────────────────────────────────────

/// The dashboard calls the gateway from a Cloudflare Worker, so the address the
/// gateway derives for a dashboard request is the WORKER's, not the admin's. The
/// Worker sees the browser's address (`cf-connecting-ip`, set by Cloudflare on the
/// inbound request) and attests it in a header signed with a secret only it and the
/// gateway hold:
///
/// `x-tracelane-client-ip-attestation: v1;<ip>;<unix-seconds>;<hex HMAC-SHA256>`
///
/// over `v1|<ip>|<unix-seconds>|<hex SHA-256 of the bearer token>` — bound to the
/// very credential on the request and to a short clock window, so a captured
/// attestation is useless with another token or a minute later. Without the secret
/// (`TRACELANE_CLIENT_IP_ATTEST_SECRET`, ≥ 32 bytes) or with a header that does not
/// verify, the header is IGNORED and the derived address applies — never trusted.
pub mod attest {
    use std::net::IpAddr;
    use std::sync::OnceLock;

    use axum::http::HeaderMap;
    use ring::hmac;
    use sha2::{Digest, Sha256};

    /// The header the dashboard sets.
    pub const HEADER: &str = "x-tracelane-client-ip-attestation";
    /// The env var holding the shared secret (gateway env + `wrangler secret put`).
    pub const SECRET_ENV: &str = "TRACELANE_CLIENT_IP_ATTEST_SECRET";
    const MIN_SECRET_BYTES: usize = 32;

    fn key() -> Option<&'static hmac::Key> {
        #[cfg(test)]
        if let Some(k) = super::test_overrides::attest_key() {
            return Some(k);
        }
        static KEY: OnceLock<Option<hmac::Key>> = OnceLock::new();
        KEY.get_or_init(|| {
            let raw = std::env::var(SECRET_ENV).ok()?;
            if raw.len() < MIN_SECRET_BYTES {
                tracing::warn!(
                    "{SECRET_ENV} is shorter than {MIN_SECRET_BYTES} bytes — dashboard client-IP attestation DISABLED"
                );
                return None;
            }
            Some(hmac::Key::new(hmac::HMAC_SHA256, raw.as_bytes()))
        })
        .as_ref()
    }

    fn token_digest(headers: &HeaderMap) -> Option<String> {
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)?
            .to_str()
            .ok()?;
        let token = auth.strip_prefix("Bearer ")?;
        Some(hex::encode(Sha256::digest(token.as_bytes())))
    }

    fn message(ip: &str, ts: i64, digest: &str) -> String {
        format!("v1|{ip}|{ts}|{digest}")
    }

    /// The attested address, if the header is present, fresh, bound to this
    /// request's bearer token, and signed with the configured secret.
    #[must_use]
    pub fn verified(headers: &HeaderMap, now: i64) -> Option<IpAddr> {
        let key = key()?;
        let raw = headers.get(HEADER)?.to_str().ok()?;
        let mut parts = raw.split(';');
        let (Some("v1"), Some(ip), Some(ts), Some(sig), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        let ip: IpAddr = ip.parse().ok()?;
        let ts: i64 = ts.parse().ok()?;
        let skew = super::policy()
            .admin_access
            .client_ip_attestation_max_skew_secs;
        if (now - ts).abs() > skew {
            return None;
        }
        let sig = hex::decode(sig).ok()?;
        let digest = token_digest(headers)?;
        hmac::verify(key, message(&ip.to_string(), ts, &digest).as_bytes(), &sig).ok()?;
        Some(ip)
    }

    /// Sign an attestation (tests, and the reference the dashboard implements).
    #[cfg(test)]
    pub fn sign(key: &hmac::Key, ip: &str, ts: i64, bearer_token: &str) -> String {
        let digest = hex::encode(Sha256::digest(bearer_token.as_bytes()));
        let tag = hmac::sign(key, message(ip, ts, &digest).as_bytes());
        format!("v1;{ip};{ts};{}", hex::encode(tag.as_ref()))
    }
}

// ── SSO-required: the session's authentication method ──────────────────────────

/// WorkOS access tokens carry the session id (`sid`) but NOT how the session
/// authenticated (`@workos-inc/authkit-nextjs` 4.0.1 `types/interfaces.d.ts:54-62`).
/// The authentication method lives on the WorkOS Session object
/// (`auth_method`: `sso` / `password` / `oauth` / `magic_code` / `passkey` /
/// `impersonation` / … — `@workos-inc/node` 9.2.0 `SessionResponse`), listed by
/// `GET /user_management/users/{user_id}/sessions`. So: re-verify the JWT, take its
/// `sid`, look the session up, cache the answer per `sid` (a session's method never
/// changes). An `impersonation` session is not SSO.
pub mod sso {
    use anyhow::{Context as _, Result, anyhow, bail};
    use secrecy::{ExposeSecret as _, SecretString};
    use serde::Deserialize;
    use std::sync::OnceLock;
    use std::time::Duration;

    use axum::http::HeaderMap;

    use crate::auth::Claims;

    #[derive(Debug, Deserialize)]
    pub(crate) struct SessionPage {
        pub data: Vec<SessionItem>,
        #[serde(default)]
        pub list_metadata: Option<ListMeta>,
    }

    #[derive(Debug, Deserialize)]
    pub(crate) struct SessionItem {
        pub id: String,
        pub auth_method: String,
        #[serde(default)]
        pub status: Option<String>,
        /// rev5 L3: the WorkOS organization the session is signed in to (the WorkOS
        /// Session object's `organization_id`; null outside an organization).
        #[serde(default)]
        pub organization_id: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub(crate) struct ListMeta {
        #[serde(default)]
        pub after: Option<String>,
    }

    /// The page's verdict on `sid`: `Some(true)` an ACTIVE SSO session signed in to
    /// `org` — this workspace's WorkOS organization (rev5 L3: an SSO session of the same
    /// user for ANOTHER organization, or one with no organization, is not this
    /// workspace's SSO); `Some(false)` found but not that; `None` not on this page.
    /// Fail-CLOSED: no `org` to bind to (a token without `org_id`) is never SSO.
    pub(crate) fn verdict(page: &SessionPage, sid: &str, org: Option<&str>) -> Option<bool> {
        page.data.iter().find(|s| s.id == sid).map(|s| {
            s.auth_method == "sso"
                && s.status.as_deref().is_none_or(|st| st == "active")
                && org.is_some_and(|o| s.organization_id.as_deref() == Some(o))
        })
    }

    fn cache() -> &'static moka::future::Cache<(String, String), bool> {
        static C: OnceLock<moka::future::Cache<(String, String), bool>> = OnceLock::new();
        C.get_or_init(|| {
            let p = &super::policy().admin_access;
            moka::future::Cache::builder()
                .max_capacity(p.sso_session_cache_max_entries)
                .time_to_live(Duration::from_secs(p.sso_session_cache_ttl_secs))
                .build()
        })
    }

    /// Is the caller's WorkOS session an active SSO session?
    ///
    /// # Errors
    /// Fail-CLOSED: no `sid`, no `WORKOS_API_KEY`, a transport or parse failure,
    /// or a session that cannot be found within the page cap — the caller refuses.
    pub async fn session_is_sso(claims: &Claims, headers: &HeaderMap) -> Result<bool> {
        #[cfg(test)]
        if let Some(over) = super::test_overrides::sso() {
            return over.map_err(|()| anyhow!("test: SSO lookup failed"));
        }
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .context("no Authorization header")?;
        let (sid, org) = crate::auth::verified_session(auth)
            .await?
            .context("the session token carries no sid")?;
        let cache_key = (sid.clone(), org.clone().unwrap_or_default());
        if let Some(hit) = cache().get(&cache_key).await {
            return Ok(hit);
        }
        let key: SecretString = std::env::var("WORKOS_API_KEY")
            .map(SecretString::from)
            .map_err(|_| anyhow!("WORKOS_API_KEY is not configured"))?;
        let is_sso = lookup(&claims.sub, &sid, org.as_deref(), &key).await?;
        cache().insert(cache_key, is_sso).await;
        Ok(is_sso)
    }

    async fn lookup(
        user_id: &str,
        sid: &str,
        org: Option<&str>,
        key: &SecretString,
    ) -> Result<bool> {
        let p = &super::policy().admin_access;
        let mut after: Option<String> = None;
        for _ in 0..p.sso_lookup_max_pages {
            let mut url = reqwest::Url::parse("https://api.workos.com").context("WorkOS URL")?;
            url.path_segments_mut()
                .map_err(|()| anyhow!("WorkOS URL cannot hold a path"))?
                .extend(["user_management", "users", user_id, "sessions"]);
            url.query_pairs_mut().append_pair("limit", "100");
            if let Some(a) = &after {
                url.query_pairs_mut().append_pair("after", a);
            }
            let page: SessionPage =
                tokio::time::timeout(Duration::from_millis(p.sso_lookup_timeout_ms), async {
                    let pinned = crate::ssrf_guard::validate_url_pinned(url.as_str()).await?;
                    let client = pinned
                        .pin(crate::ssrf_guard::safe_client_builder())
                        .build()?;
                    let resp = client
                        .get(url.clone())
                        .bearer_auth(key.expose_secret())
                        .send()
                        .await
                        .map_err(|e| {
                            anyhow!("WorkOS sessions transport failed: {}", e.without_url())
                        })?;
                    if !resp.status().is_success() {
                        bail!(
                            "WorkOS sessions request refused ({})",
                            resp.status().as_u16()
                        );
                    }
                    resp.json::<SessionPage>()
                        .await
                        .map_err(|_| anyhow!("WorkOS sessions response invalid"))
                })
                .await
                .context("WorkOS sessions lookup timed out")??;
            if let Some(v) = verdict(&page, sid, org) {
                return Ok(v);
            }
            match page.list_metadata.and_then(|m| m.after) {
                Some(a) if !a.is_empty() => after = Some(a),
                _ => break,
            }
        }
        bail!("the WorkOS session was not found")
    }
}

// ── Test overrides (compiled out of every non-test build) ──────────────────────

#[cfg(test)]
pub(crate) mod test_overrides {
    use std::cell::RefCell;

    use crate::db::admin_security::AdminAccess;

    thread_local! {
        static ACCESS: RefCell<Option<Result<AdminAccess, ()>>> = const { RefCell::new(None) };
        static SSO: RefCell<Option<Result<bool, ()>>> = const { RefCell::new(None) };
        static KEY: RefCell<Option<&'static ring::hmac::Key>> = const { RefCell::new(None) };
    }

    pub(crate) fn access() -> Option<Result<AdminAccess, ()>> {
        ACCESS.with(|a| a.borrow().clone())
    }
    pub(crate) fn sso() -> Option<Result<bool, ()>> {
        SSO.with(|s| *s.borrow())
    }
    pub(crate) fn attest_key() -> Option<&'static ring::hmac::Key> {
        KEY.with(|k| *k.borrow())
    }

    /// Present these overrides on this thread until dropped.
    pub(crate) struct Guard;
    impl Guard {
        pub(crate) fn new(
            access: Option<Result<AdminAccess, ()>>,
            sso: Option<Result<bool, ()>>,
            key: Option<&'static ring::hmac::Key>,
        ) -> Self {
            ACCESS.with(|a| *a.borrow_mut() = access);
            SSO.with(|s| *s.borrow_mut() = sso);
            KEY.with(|k| *k.borrow_mut() = key);
            Self
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            ACCESS.with(|a| *a.borrow_mut() = None);
            SSO.with(|s| *s.borrow_mut() = None);
            KEY.with(|k| *k.borrow_mut() = None);
        }
    }

    thread_local! {
        static RATE: std::cell::Cell<Option<(u32, u32, u32, u32)>> = const { std::cell::Cell::new(None) };
    }

    /// rev5 M7: the per-minute caps this thread's control requests run under —
    /// `(control routes, web control changes, channel tests, incident controls)`.
    /// `None` (no guard) = NOT limited in a test build: the suite shares a handful of
    /// fixed tenants across hundreds of control calls, and a production-sized cap would
    /// make unrelated tests 429 at random. The limiter code is the production code; only
    /// the number is pinned.
    pub(crate) fn rate() -> Option<(u32, u32, u32, u32)> {
        RATE.with(std::cell::Cell::get)
    }

    pub(crate) struct RateGuard;
    impl RateGuard {
        pub(crate) fn set(routes_per_minute: u32, web_changes_per_minute: u32) -> Self {
            Self::set3(routes_per_minute, web_changes_per_minute, 1_000)
        }

        pub(crate) fn set3(routes: u32, web_changes: u32, channel_tests: u32) -> Self {
            Self::set4(routes, web_changes, channel_tests, 1_000)
        }

        pub(crate) fn set4(
            routes: u32,
            web_changes: u32,
            channel_tests: u32,
            incident: u32,
        ) -> Self {
            RATE.with(|r| r.set(Some((routes, web_changes, channel_tests, incident))));
            Self
        }
    }
    impl Drop for RateGuard {
        fn drop(&mut self) {
            RATE.with(|r| r.set(None));
        }
    }
}

// ── Routes ─────────────────────────────────────────────────────────────────────

/// `GET`/`PUT /v1/security/admin-access` and `GET`/`POST /v1/audit/control-changes`.
/// Mounted only with a Postgres control plane (`server.rs`), like every
/// Postgres-gated group; without one there is nothing to configure or read.
pub fn router(pool: DbPool) -> Router {
    Router::new()
        .route(
            "/v1/security/admin-access",
            get(get_admin_access).put(put_admin_access),
        )
        .route(
            "/v1/audit/control-changes",
            get(list_control_changes).post(record_web_change),
        )
        .with_state(pool)
}

fn json_err(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": code, "message": message}).to_string(),
    )
        .into_response()
}

async fn authenticate(headers: &HeaderMap) -> Result<Claims, Response> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(json_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing Authorization header",
        ));
    }
    crate::auth::validate_authorization(auth)
        .await
        .map_err(|e| {
            let (status, msg) = crate::auth::failure(&e);
            json_err(status, crate::auth::failure_code(&e), msg)
        })
}

#[derive(Debug, Serialize)]
struct AdminAccessView {
    admin_ip_allowlist: Vec<String>,
    sso_required: bool,
    updated_at: Option<DateTime<Utc>>,
    updated_by: Option<String>,
    /// The address the gateway checks the allowlist against for THIS request.
    your_ip: Option<String>,
    /// Whether `your_ip` came from the dashboard's signed attestation.
    your_ip_attested: bool,
    max_ip_allowlist_entries: usize,
}

fn view(access: &AdminAccess, ip: Option<IpAddr>, attested: bool) -> AdminAccessView {
    AdminAccessView {
        admin_ip_allowlist: access.admin_ip_allowlist.clone(),
        sso_required: access.sso_required,
        updated_at: access.updated_at,
        updated_by: access.updated_by.clone(),
        your_ip: ip.map(|i| i.to_string()),
        your_ip_attested: attested,
        max_ip_allowlist_entries: policy().admin_access.max_ip_allowlist_entries,
    }
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn get_admin_access(headers: HeaderMap) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    match require_control(&claims, Capability::ManageSecurity, &headers).await {
        Ok(actor) => Json(view(
            &actor.access,
            actor.client_ip,
            actor.client_ip_attested,
        ))
        .into_response(),
        Err(r) => r.into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminAccessBody {
    admin_ip_allowlist: Option<Vec<String>>,
    sso_required: Option<bool>,
    /// The owner's explicit "yes, this may lock me out" (lock-out guard).
    #[serde(default)]
    acknowledge_lockout: bool,
}

/// Validate and canonicalise an allowlist: every entry a CIDR (host bits clear),
/// no duplicates, at most the reference-table cap. Pure.
fn validate_allowlist(raw: &[String]) -> Result<Vec<String>, String> {
    let max = policy().admin_access.max_ip_allowlist_entries;
    if raw.len() > max {
        return Err(format!("at most {max} CIDR blocks are allowed"));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for entry in raw {
        let e = entry.trim();
        if Cidr::parse(e).is_none() {
            return Err(format!(
                "`{}` is not a CIDR block (e.g. 203.0.113.0/24 or 2001:db8::/48; host bits must be zero)",
                e.chars().take(64).collect::<String>()
            ));
        }
        if !out.iter().any(|o| o == e) {
            out.push(e.to_owned());
        }
    }
    Ok(out)
}

/// Would `allowlist` refuse `ip`? (`None` = the address could not be proven.)
fn locks_out(allowlist: &[String], ip: Option<IpAddr>) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    let Some(ip) = ip else { return true };
    !allowlist
        .iter()
        .filter_map(|c| Cidr::parse(c))
        .any(|c| c.contains(ip))
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn put_admin_access(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    body: Result<Json<AdminAccessBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let actor = match require_control(&claims, Capability::ManageSecurity, &headers).await {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    let Json(body) = match body {
        Ok(b) => b,
        Err(e) => {
            return json_err(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                &format!(
                    "expected {{admin_ip_allowlist?, sso_required?, acknowledge_lockout?}}: {}",
                    e.body_text()
                ),
            );
        }
    };
    let allowlist = match body.admin_ip_allowlist.as_deref() {
        Some(raw) => match validate_allowlist(raw) {
            Ok(v) => v,
            Err(m) => return json_err(StatusCode::BAD_REQUEST, "invalid_cidr", &m),
        },
        None => actor.access.admin_ip_allowlist.clone(),
    };
    let sso_required = body.sso_required.unwrap_or(actor.access.sso_required);

    // Lock-out guard: refuse a policy that would refuse THIS caller, unless they
    // say, explicitly, that they mean it. The operator break-glass
    // (`scripts/ops/break-glass-admin-access.sh`) is the way back.
    if !body.acknowledge_lockout {
        if locks_out(&allowlist, actor.client_ip) {
            return (
                StatusCode::CONFLICT,
                [(header::CONTENT_TYPE, "application/json")],
                json!({
                    "error": "would_lock_you_out",
                    "reason": "ip",
                    "message": "this allowlist does not include the address this request came from, so it would block your own next admin action. Add your address, or resend with acknowledge_lockout: true.",
                    "your_ip": actor.client_ip.map(|i| i.to_string()),
                    "your_ip_attested": actor.client_ip_attested,
                })
                .to_string(),
            )
                .into_response();
        }
        if sso_required
            && !actor.access.sso_required
            && matches!(claims.auth_method, crate::auth::AuthMethod::JwtBearer)
        {
            match sso::session_is_sso(&claims, &headers).await {
                Ok(true) => {}
                Ok(false) => {
                    return (
                        StatusCode::CONFLICT,
                        [(header::CONTENT_TYPE, "application/json")],
                        json!({
                            "error": "would_lock_you_out",
                            "reason": "sso",
                            "message": "you are not signed in through SSO, so requiring SSO would block your own next admin action. Sign in through your identity provider first, or resend with acknowledge_lockout: true.",
                        })
                        .to_string(),
                    )
                        .into_response();
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SSO-required enable: own-session check failed");
                    return json_err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "sso_unverifiable",
                        "your session's sign-in method could not be verified, so SSO-required was not enabled — retry, or resend with acknowledge_lockout: true",
                    );
                }
            }
        }
    }

    match crate::db::admin_security::put(
        &pool,
        &actor.tenant_id,
        &allowlist,
        sso_required,
        &actor.audit,
    )
    .await
    {
        Ok((_, after)) => {
            Json(view(&after, actor.client_ip, actor.client_ip_attested)).into_response()
        }
        Err(e) => {
            tracing::warn!(tenant_id = %actor.tenant_id, error = %crate::db::pg_error_chain(&e), "admin access update failed (audited write refused or store error)");
            json_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "control_change_unavailable",
                "the change could not be recorded, so it was not applied — retry",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    action: Option<String>,
    target_type: Option<String>,
    cursor: Option<i64>,
    limit: Option<i64>,
    format: Option<String>,
}

#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_control_changes(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    params: Result<Query<ListParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let actor = match require_control(&claims, Capability::ReadControlAudit, &headers).await {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    let Query(p) = match params {
        Ok(p) => p,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, "invalid_query", &e.body_text()),
    };
    let ndjson = match p.format.as_deref() {
        None | Some("json") => false,
        Some("ndjson") => true,
        Some(_) => {
            return json_err(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "format must be json or ndjson",
            );
        }
    };
    let pol = &policy().control_audit;
    let limit = p.limit.unwrap_or(pol.page_default);
    if !(1..=pol.page_max).contains(&limit) {
        return json_err(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            &format!("limit must be between 1 and {}", pol.page_max),
        );
    }
    let q = ListQuery {
        since: p.since,
        until: p.until,
        action: p.action,
        target_type: p.target_type,
        before_id: p.cursor,
        limit,
    };
    let rows = match control_audit::list(&pool, &actor.tenant_id, &q).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(tenant_id = %actor.tenant_id, error = %crate::db::pg_error_chain(&e), "control-change list failed");
            return json_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "control_audit_unavailable",
                "the control-change trail could not be read — retry",
            );
        }
    };
    // A full page MAY have more behind it; a short page is the end.
    let next_cursor = (i64::try_from(rows.len()).unwrap_or(i64::MAX) == limit)
        .then(|| rows.last().map(|r| r.id))
        .flatten();
    if ndjson {
        let mut out = String::new();
        for r in &rows {
            if let Ok(line) = serde_json::to_string(r) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        let mut resp = Response::new(Body::from(out));
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/x-ndjson"),
        );
        if let Some(c) = next_cursor
            && let Ok(v) = header::HeaderValue::from_str(&c.to_string())
        {
            resp.headers_mut().insert("x-next-cursor", v);
        }
        return resp;
    }
    Json(json!({"items": rows, "next_cursor": next_cursor})).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebChangeBody {
    action: String,
    target_id: String,
    #[serde(default)]
    before: Option<Value>,
    #[serde(default)]
    after: Option<Value>,
}

const TARGET_ID_MAX: usize = 256;

/// `POST /v1/audit/control-changes` — the dashboard records a change it is about to
/// make outside the gateway (WorkOS team calls, its own CMK / workspace writes).
/// Only actions in `WEB_CONTROL_ACTIONS`, each behind its own capability, the IP
/// allowlist and SSO-required — the same gate as a gateway control route. The actor
/// and tenant are the caller's verified claims; the target type is derived from the
/// action, never taken from the body.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn record_web_change(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    body: Result<Json<WebChangeBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    let Json(body) = match body {
        Ok(b) => b,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, "invalid_body", &e.body_text()),
    };
    let Some(cap) = web_action_capability(&body.action) else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "unknown_action",
            "this endpoint records only the dashboard's own control changes (member.*, workspace.*, cmk.*)",
        );
    };
    // rev6 N1: removing a member is an incident control — its own per-principal bucket
    // (which also bounds its undeletable rows), never the shared or web-change ones.
    let is_incident = INCIDENT_WEB_ACTIONS.contains(&body.action.as_str());
    let gate = if is_incident {
        incident(cap)
    } else {
        ControlGate::from(cap)
    };
    let actor = match require_control(&claims, gate, &headers).await {
        Ok(a) => a,
        Err(r) => return r.into_response(),
    };
    // rev5 M7: its own, tighter bucket — every accepted call is a row nothing deletes.
    // Per (workspace, principal) since rev6 N1.
    if !is_incident
        && let Err(r) = charge_control_rate(
            &actor.tenant_id,
            Some(&claims.sub),
            ControlBucket::WebChanges,
        )
    {
        return r.into_response();
    }
    if body.target_id.is_empty() || body.target_id.len() > TARGET_ID_MAX {
        return json_err(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            &format!("target_id must be 1..={TARGET_ID_MAX} bytes"),
        );
    }
    let max = policy().control_audit.change_json_max_bytes;
    let mut total = 0usize;
    for v in [&body.before, &body.after].into_iter().flatten() {
        let n = v.to_string().len();
        total = total.saturating_add(n);
        if n > max {
            return json_err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "change_too_large",
                &format!("before/after must each serialise to at most {max} bytes"),
            );
        }
    }
    // rev5 M7: the WHOLE change too — each half under its cap still wrote ~2x it.
    let whole = policy().control_audit.web_change_max_bytes;
    if total > whole {
        return json_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "change_too_large",
            &format!("before and after together must serialise to at most {whole} bytes"),
        );
    }
    let target_type = body.action.split('.').next().unwrap_or("web");
    let change = Change {
        action: &body.action,
        target_type,
        target_id: body.target_id.clone(),
        before: body.before,
        after: body.after,
    };
    match control_audit::record_standalone(&pool, &actor.tenant_id, &actor.audit, change).await {
        Ok(id) => (
            StatusCode::CREATED,
            Json(json!({"id": id, "request_id": actor.audit.request_id})),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(tenant_id = %actor.tenant_id, error = %crate::db::pg_error_chain(&e), "web control change could not be recorded");
            json_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "control_audit_unavailable",
                "the change could not be recorded, so it must not be made — retry",
            )
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, debug_assertions))]
mod pg_tests;
