//! Persisted per-tenant-per-period quota-notification marker (SET-08).
//!
//! # Why this exists
//!
//! The first cut of the soft cap fired on the transition `used == quota`, where
//! `used` came from the in-memory [`crate::rate_limiter::QuotaTracker`]. That
//! the equality is unsound across a restart — and a mid-month deploy is a
//! restart:
//!
//! * a restart landing the counter **above** quota never observes `== quota`
//!   again, so the tenant is **never told** they reached 100%; the alert is lost
//!   with no error anywhere. That is the [`docs/reference/TRAPS.md`]
//!   green-while-broken shape: the code runs, the test passes, the customer
//!   hears nothing.
//! * a restart landing it **below** quota re-crosses and fires a **second**
//!   time.
//!
//! So the predicate became the position test `used >= quota`, and fire-once
//! moved here — to state that outlives the process.
//!
//! # Why the claim is an INSERT, not a SELECT-then-INSERT
//!
//! The primary key `(tenant_id, period, kind)` **is** the concurrency control.
//! `INSERT … ON CONFLICT DO NOTHING` returns 1 row affected for exactly one
//! caller, so two gateway replicas racing the same crossing produce exactly one
//! notification with no read-modify-write window. A `SELECT … IF NOT EXISTS
//! THEN INSERT` would double-fire under the second replica the scale ladder
//! already plans for (`GWY-C4`/`GWY-C5`).
//!
//! # Cost
//!
//! One INSERT per tenant per period per kind, issued from a spawned task — never
//! on the request path. The caller additionally holds a process-local "already
//! attempted" set so a tenant sitting above quota does not spawn a task per
//! request. CLAUDE.md's "never per-request Postgres" invariant holds.

use anyhow::Result;

use super::Pool;
use tracelane_shared::TenantId;

/// Notification kind. Text in the DB, not a PG enum — binding a Rust `&str`
/// into a PG enum needs a `$N::text::enum` cast and has already cost this repo
/// one debugging session.
pub const KIND_SOFT_CAP: &str = "soft_cap";

/// Attempt to claim the right to notify `tenant_id` for `period`/`kind`.
///
/// Returns `Ok(true)` when THIS caller claimed it (and must therefore send the
/// notification), `Ok(false)` when someone else already did — another replica,
/// or this process before a restart.
///
/// # Errors
/// Propagates the Postgres error. The caller treats an error as "do not
/// notify": a failed claim must not be retried into a duplicate alert, and a
/// missed alert is strictly better than a flood that trains the tenant to mute
/// the channel their hard-cap 429 also arrives on.
pub async fn claim(pool: &Pool, tenant_id: &TenantId, period: &str, kind: &str) -> Result<bool> {
    let client = pool.get().await?;
    let stmt = client
        .prepare_cached(
            "INSERT INTO quota_notifications (tenant_id, period, kind)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id, period, kind) DO NOTHING",
        )
        .await?;
    let affected = client
        .execute(&stmt, &[tenant_id.as_uuid(), &period, &kind])
        .await?;
    Ok(affected == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kind string is part of the primary key, so a typo silently creates a
    /// second marker and re-enables the double-fire this table exists to stop.
    #[test]
    fn soft_cap_kind_is_stable() {
        assert_eq!(KIND_SOFT_CAP, "soft_cap");
    }
}
