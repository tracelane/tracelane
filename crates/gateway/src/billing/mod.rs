//! Polar.sh billing integration.
//!
//! Single-purpose module: build the wire-shape for customer, event-
//! recording, and customer-portal calls against the Polar REST API.
//! Polar handles Stripe under the hood; Tracelane never integrates with
//! Stripe directly.
//!
//! The gateway hot path does NOT call Polar synchronously; meter
//! events are queued via `meter::Recorder::record(...)` and flushed by
//! a background task. The customer and portal paths are called from
//! the tenant-onboarding flow.
//!
//! API key handling:
//!   - Read once from `POLAR_ACCESS_TOKEN`.
//!   - Never logged. `tracing::instrument` skips the api_key argument.
//!   - Wrapped in `secrecy::SecretString` with `Zeroize`-on-drop.
//!
//! Plans + meters:
//!   `crate::clickhouse_query::PlanTier` (Free/Builder/Team/Business/Enterprise)
//!     is the live tier enum — this module's own copy was deleted 2026-09-12
//!     (B-390), zero readers
//!   Meter::{TokensProcessed, AuditAnchors} — event names on Polar's
//!     /events/ingest endpoint
//!
//! See `.claude/rules/billing.md` for the canonical rules.

/// BILL-01 / ADR-076 §2.3 — read-side rehydration of content-addressed blobs
/// ingest substitutes into oversized attribute values.
pub mod blobs;
pub mod checkout;
/// BILL-01 / ADR-076 step 8 — usage-warning emails (75%/90% of an included
/// allowance), sent by the daily metering job.
pub mod email;

/// BILL-01 / ADR-076 — the daily metering job (meters 2-5: hot window,
/// series, query, cold) + Polar usage emission + weekly blob GC.
pub mod metering_job;
/// BILL-01 / ADR-076 — the six-meter usage model's gateway half (ingest
/// bytes, eval runs, per-key token/spend sub-meters). Distinct from `meter`
/// (singular — the legacy Polar `TokensProcessed`/`AuditAnchors` recorder,
/// unchanged): two systems billing two different things, not a rename.
pub mod meters;
pub mod polar_client;
pub mod portal;
/// BILL-01 / ADR-076 — the pure rating engine (bands, burst exemption) plus
/// the `RateCard`/`Policy` loaded from `pricing_rates` + `billing_policy`.
pub mod rating;
pub mod usage;
/// BILL-01 / ADR-076 A3 — the velocity breaker (a per-key token-generation
/// anomaly detector that freezes prompt promotion).
pub mod velocity_breaker;

pub use meters::{MeterSink, UsageMeter};
pub use polar_client::PolarClient;
pub use portal::PortalState;
pub use rating::RateCard;

// NOTE: the Polar webhook RECEIVER lives in the web tier
// (`apps/web/app/api/webhooks/polar`), the single correct handler. The former
// gateway `webhook` module (a second, incomplete receiver keyed only on
// `polar_customer_id`) was retired 2026-07-28 — one receiver, no drift.

/// Hosts permitted as a billing redirect target — `success_url` / `cancel_url`
/// on checkout (A21) and `return_url` on the customer portal (SET-18).
///
/// # Why this lives here and not in `checkout.rs`
///
/// It was checkout-local, and `portal.rs` carried `TODO: allowlist` instead —
/// the same defence, one file over, never called. A shared validator is what
/// makes "every billing redirect target is allowlisted" a property of the
/// module rather than a habit of whoever wrote each handler.
///
/// **The portal parameter is currently dead on the wire** — Polar's
/// `/customer-sessions/` takes no return URL, so `polar_client.rs` binds it as
/// `_return_url` and never puts it in the body. That makes the redirect latent,
/// not live, and it is exactly why the check belongs here: the value is
/// accepted from the caller today, so the day anyone wires it through, the
/// allowlist is already in front of it instead of a TODO.
///
/// Allowlist permits `tracelane.dev` and any subdomain. Debug builds may set
/// `TRACELANE_BILLING_TEST_ANY_HOST=1` to bypass the check for local
/// integration tests; release builds ignore the env var entirely.
///
/// # Errors
/// **Fail-CLOSED** (security path, CLAUDE.md §10): anything not provably on the
/// allowlist is rejected — unparseable, non-https, hostless, or off-host.
pub(crate) fn validate_redirect_url(url: &str) -> Result<(), &'static str> {
    #[cfg(debug_assertions)]
    if std::env::var("TRACELANE_BILLING_TEST_ANY_HOST").as_deref() == Ok("1") {
        return Ok(());
    }

    let parsed = reqwest::Url::parse(url).map_err(|_| "not a valid URL")?;
    match parsed.scheme() {
        "https" => {}
        "http" if cfg!(debug_assertions) => {}
        _ => return Err("scheme must be https"),
    }
    let host = parsed
        .host_str()
        .ok_or("URL missing host")?
        .to_ascii_lowercase();
    if host == "tracelane.dev" || host.ends_with(".tracelane.dev") {
        Ok(())
    } else {
        Err("host not on the allowlist (*.tracelane.dev)")
    }
}

// `PlanTier` (this module's own copy — Free/Builder/Team/Business/Enterprise
// with `metadata_key()`/`as_str()`) was deleted 2026-09-12 (B-390) — zero
// readers anywhere in the tree. `crates/gateway/src/clickhouse_query.rs`
// carries the live `PlanTier` used throughout the crate, and its own doc
// comment says why it exists as a second copy: "mirrors the Polar/ADR-020
// plan keys without pulling in the full billing crate" — this was the
// original it was mirroring, orphaned once every caller moved to the mirror.
