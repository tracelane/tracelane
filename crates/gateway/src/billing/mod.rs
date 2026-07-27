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
pub mod webhook;

pub use meter::{Meter, Recorder};
pub use polar_client::{
    BillingError, BillingResult, PolarClient, PolarCustomerId, PolarSubscriptionId,
};
pub use portal::PortalState;
pub use webhook::{WebhookConfig, WebhookState};

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
