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
//!   PlanTier::{Free, Builder, Team, Business, Enterprise} — string form
//!     is the `lookup_key` value in the Polar product's metadata
//!   Meter::{TokensProcessed, AuditAnchors} — event names on Polar's
//!     /events/ingest endpoint
//!
//! See `.claude/rules/billing.md` for the canonical rules.

pub mod checkout;
pub mod meter;
pub mod polar_client;
pub mod portal;
pub mod usage;

pub use meter::{Meter, Recorder};
pub use polar_client::{
    BillingError, BillingResult, PolarClient, PolarCustomerId, PolarSubscriptionId,
};
pub use portal::PortalState;

// NOTE: the Polar webhook RECEIVER lives in the web tier
// (`apps/web/app/api/webhooks/polar`), the single correct handler. The former
// gateway `webhook` module (a second, incomplete receiver keyed only on

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

/// Plan tier the customer is on. The string form is the
/// `lookup_key` value in the Polar product's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanTier {
    Free,
    Builder,
    Team,
    Business,
    Enterprise,
}

impl PlanTier {
    /// Value of `product.metadata.lookup_key` in Polar (unprefixed, set in the
    /// Polar dashboard May 2026 — not the draft `tracelane_*` form).
    pub fn metadata_key(&self) -> &'static str {
        match self {
            PlanTier::Free => "free_v1",
            PlanTier::Builder => "builder_v1",
            PlanTier::Team => "team_v1",
            PlanTier::Business => "business_v1",
            PlanTier::Enterprise => "enterprise_v1",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PlanTier::Free => "free",
            PlanTier::Builder => "builder",
            PlanTier::Team => "team",
            PlanTier::Business => "business",
            PlanTier::Enterprise => "enterprise",
        }
    }
}
