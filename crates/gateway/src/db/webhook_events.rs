//! Webhook event deduplication.
//!
//! Polar and WorkOS both retry on any non-2xx response, and Polar's
//! Standard Webhooks signature window allows a signed event to be replayed
//! within 5 minutes. Without dedup, every retry runs the side-effect path
//! again — set_plan_tier, INSERT INTO users, etc.
//!
//! [`try_record_processed`] inserts `(source, event_id)` with
//! `ON CONFLICT DO NOTHING`. The function returns `true` if this is
//! the FIRST time we've seen the event (caller proceeds with handling),
//! `false` if it was already recorded (caller skips side effects and
//! returns 200).
//!

use anyhow::{Context as _, Result};
use deadpool_postgres::Pool;
use tracing::instrument;

/// Event source identifier. Used as the first column of the composite
/// primary key so different webhook providers don't collide on the
/// same opaque event-id string.
#[derive(Debug, Clone, Copy)]
pub enum WebhookSource {
    /// Polar.sh — Standard Webhooks signing. Canonical payment provider.
    Polar,
    /// WorkOS — auth provider (organisation lifecycle).
    WorkOs,
}

impl WebhookSource {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Polar => "polar",
            Self::WorkOs => "workos",
        }
    }
}

/// Cheap read-side check: has `(source, event_id)` been recorded?
///
/// Used as a pre-flight in webhook handlers — when `true`, skip
/// dispatch and ack 200 immediately. When `false`, run dispatch and
/// then call [`try_record_processed`] on success.
#[instrument(skip(pool), fields(source = source.as_str(), event_id = %event_id))]
pub async fn already_processed(pool: &Pool, source: WebhookSource, event_id: &str) -> Result<bool> {
    let client = pool.get().await.context("acquire pg client")?;
    let row = client
        .query_opt(
            "SELECT 1 FROM webhook_events WHERE source = $1 AND event_id = $2",
            &[&source.as_str(), &event_id],
        )
        .await
        .context("SELECT FROM webhook_events")?;
    Ok(row.is_some())
}

/// Record an event as processed AFTER successful dispatch.
///
/// Returns:
/// - `Ok(true)` — INSERT succeeded; this is the first record. Normal path.
/// - `Ok(false)` — INSERT collided with a concurrent retry that already
///   recorded the event. The other request also ran dispatch; both
///   side effects ran, but downstream ops (set_plan_tier etc.) are
///   idempotent so the duplicate is harmless.
/// - `Err` — Postgres failure. Caller logs but does NOT 5xx, because
///   the side effect already ran.
#[instrument(skip(pool), fields(source = source.as_str(), event_id = %event_id))]
pub async fn try_record_processed(
    pool: &Pool,
    source: WebhookSource,
    event_id: &str,
) -> Result<bool> {
    let client = pool.get().await.context("acquire pg client")?;
    let rows = client
        .execute(
            "INSERT INTO webhook_events (source, event_id) VALUES ($1, $2) \
             ON CONFLICT (source, event_id) DO NOTHING",
            &[&source.as_str(), &event_id],
        )
        .await
        .context("INSERT INTO webhook_events")?;
    Ok(rows == 1)
}
