//! BILL-01 / ADR-076 A3 — the velocity breaker.
//!
//! Every `Policy::velocity_interval_secs` (default 300s), reads ALL keys'
//! daily `key_output_tokens` meter history in ONE ClickHouse `GROUP BY`
//! query and the set of velocity-breaker-enabled keys in ONE Postgres query
//! — spec §2.5b: "1 query per 5-min tick over ALL keys, not per key". A key
//! whose TODAY total exceeds `mean + sigma * stddev` of its own trailing
//! window (>= 3 days of history required, else it never trips) freezes its
//! TENANT's prompt promotion — `prompt_routes` reads
//! `ResolvedEntitlements.is_promotion_frozen()` and returns `423` on
//! promote/rollback while it is set. ONE UPDATE, only on a trip, never a
//! per-key or per-tenant write on every tick.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use uuid::Uuid;

use crate::billing::rating::RateCard;

#[derive(serde::Deserialize, clickhouse::Row, Debug, Clone)]
struct KeyVelocityRow {
    tenant_id: String,
    dim: String, // the key id, as a string (meter_counters.dim)
    today: f64,
    mean_prior: f64,
    stddev_prior: f64,
    days_of_history: u64,
}

/// One tick: read, decide, write (only on a trip). Never per-key I/O.
///
/// `# Errors`: none returned — every failure is fail-OPEN (a read/write
/// failure here means the breaker misses a tick, never that it blocks
/// promotion by accident; CLAUDE.md §10, a fault-tolerance path).
pub async fn tick(pg: &crate::db::DbPool, ch_url: &str, card: &RateCard) {
    let window_days = card.policy.velocity_window_days.max(1);
    let sigma = card.policy.velocity_sigma;

    // ONE ClickHouse GROUP BY over every (tenant, key) that has ANY
    // key_output_tokens history — not one query per key.
    let sql = format!(
        "SELECT tenant_id, dim, \
            sumIf(value, day = today()) AS today, \
            avgIf(value, day < today() AND day >= today() - {window_days}) AS mean_prior, \
            stddevPopIf(value, day < today() AND day >= today() - {window_days}) AS stddev_prior, \
            countIf(day < today() AND day >= today() - {window_days}) AS days_of_history \
         FROM tracelane.meter_counters \
         WHERE meter = 'key_output_tokens' AND dim != '' \
         GROUP BY tenant_id, dim"
    );
    let rows: Vec<KeyVelocityRow> = match crate::clickhouse_query::ch_client(ch_url.to_string())
        .query(&crate::clickhouse_query::ceiling(&sql))
        .fetch_all()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "velocity breaker: meter_counters read failed; skipping this tick");
            return;
        }
    };
    if rows.is_empty() {
        return;
    }

    // ONE Postgres query for the whole opt-in set — never per key.
    let client = match pg.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "velocity breaker: pool unavailable; skipping this tick");
            return;
        }
    };
    let enabled: HashSet<Uuid> = match client
        .query(
            "SELECT id FROM api_keys WHERE velocity_breaker = true AND revoked_at IS NULL",
            &[],
        )
        .await
    {
        Ok(rows) => rows.iter().map(|r| r.get::<_, Uuid>(0)).collect(),
        Err(e) => {
            tracing::warn!(error = %e, "velocity breaker: api_keys read failed; skipping this tick");
            return;
        }
    };
    if enabled.is_empty() {
        return;
    }

    // Dedupe: at most one freeze WRITE per tenant per tick, even if several
    // of its keys trip in the same window — "1 UPDATE only on a trip", not
    // one per tripped key.
    let mut to_freeze: HashMap<Uuid, String> = HashMap::new();
    for row in &rows {
        let Ok(key_id) = Uuid::parse_str(&row.dim) else {
            continue;
        };
        if !enabled.contains(&key_id) {
            continue;
        }
        if row.days_of_history < 3 {
            continue; // not enough signal to call anything a spike
        }
        let threshold = row.mean_prior + sigma * row.stddev_prior;
        if threshold.is_finite() && row.today > threshold {
            let Ok(tenant_id) = Uuid::parse_str(&row.tenant_id) else {
                continue;
            };
            to_freeze.entry(tenant_id).or_insert_with(|| {
                format!(
                    "{key_id}: {:.0} tokens today vs {:.0}\u{b1}{:.0} (trailing {window_days}d)",
                    row.today, row.mean_prior, row.stddev_prior
                )
            });
        }
    }

    for (tenant_id, reason) in to_freeze {
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::VelocityBreakerTripped,
        );
        match client
            .execute(
                "UPDATE tenants SET promotion_frozen_at = now(), promotion_frozen_reason = $2 \
                 WHERE id = $1",
                &[&tenant_id, &reason],
            )
            .await
        {
            Ok(_) => tracing::warn!(
                tenant_id = %tenant_id,
                reason = %reason,
                "velocity breaker tripped — prompt promotion frozen"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "velocity breaker: freeze UPDATE failed"
            ),
        }
    }
}

/// Clear a tenant's freeze (`DELETE /v1/billing/promotion-freeze`, admin
/// scope). Idempotent — clearing an already-clear tenant is a no-op 200, not
/// a 404: a human should never have to check state before fixing it.
///
/// # Errors
/// Propagates a pool/query failure; the route surfaces it as `503`.
pub async fn clear_freeze(pg: &crate::db::DbPool, tenant_id: Uuid) -> anyhow::Result<()> {
    let client = pg
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("promotion-freeze clear pool: {e}"))?;
    client
        .execute(
            "UPDATE tenants SET promotion_frozen_at = NULL, promotion_frozen_reason = NULL \
             WHERE id = $1",
            &[&tenant_id],
        )
        .await
        .map_err(|e| anyhow::anyhow!("promotion-freeze clear: {e}"))?;
    Ok(())
}

/// Spawn the background tick loop. Re-reads `card.policy.velocity_interval_secs`
/// on every iteration, so a `billing_policy` change takes effect on the NEXT
/// tick without a redeploy.
pub fn spawn(pg: crate::db::DbPool, ch_url: String, card: Arc<ArcSwap<RateCard>>) {
    tokio::spawn(async move {
        loop {
            let interval_secs = card.load().policy.velocity_interval_secs.max(30);
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            tick(&pg, &ch_url, &card.load()).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pure decision only — "does this row trip?" — without any I/O,
    /// mirroring the exact predicate `tick` applies per row.
    fn trips(today: f64, mean_prior: f64, stddev_prior: f64, days: u64, sigma: f64) -> bool {
        if days < 3 {
            return false;
        }
        let threshold = mean_prior + sigma * stddev_prior;
        threshold.is_finite() && today > threshold
    }

    /// A fixed series: 7 days at [100, 110, 90, 105, 95, 100, 108], then a
    /// spike to 500. Mean ≈ 101.14, population stddev ≈ 6.65; 2σ ≈ 13.3, so
    /// threshold ≈ 114.4 — the spike (500) trips, the ordinary run does not.
    #[test]
    fn a_fixed_series_trips_only_on_the_real_spike() {
        let series = [100.0_f64, 110.0, 90.0, 105.0, 95.0, 100.0, 108.0];
        let mean = series.iter().sum::<f64>() / series.len() as f64;
        let variance = series.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / series.len() as f64;
        let stddev = variance.sqrt();
        assert!(
            !trips(108.0, mean, stddev, series.len() as u64, 2.0),
            "a day WITHIN the series' own range must not trip"
        );
        assert!(
            trips(500.0, mean, stddev, series.len() as u64, 2.0),
            "a genuine 5x-of-normal spike must trip"
        );
    }

    #[test]
    fn fewer_than_three_days_of_history_never_trips() {
        assert!(!trips(1_000_000.0, 1.0, 0.1, 0, 2.0));
        assert!(!trips(1_000_000.0, 1.0, 0.1, 1, 2.0));
        assert!(!trips(1_000_000.0, 1.0, 0.1, 2, 2.0));
    }

    #[test]
    fn zero_variance_history_does_not_divide_by_zero_or_panic() {
        // Every prior day identical (stddev 0): any value ABOVE the mean trips,
        // anything at or below does not. Must not panic or produce NaN chaos.
        assert!(trips(101.0, 100.0, 0.0, 5, 2.0));
        assert!(!trips(100.0, 100.0, 0.0, 5, 2.0));
    }

    /// Against a REAL Postgres: freezing then clearing a tenant round-trips,
    /// and clearing an already-clear tenant is a no-op success (idempotent),
    /// matching the entitlement resolver's real-Postgres-gated test pattern.
    ///
    /// Run: `POSTGRES_URL=<neon> cargo test -p gateway --bin gateway \
    ///   billing::velocity_breaker::tests::clear_freeze_round_trips_and_is_idempotent \
    ///   -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "needs a real Postgres with the BILL-01 (0040) migration applied; set POSTGRES_URL"]
    async fn clear_freeze_round_trips_and_is_idempotent() {
        let pool = crate::db::build_pool().await.expect("build_pool");
        let client = pool.get().await.expect("client");
        let tenant_id = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO tenants (id, workos_org_id, plan, promotion_frozen_at,                  promotion_frozen_reason) VALUES ($1, $2, 'team'::text::plan, now(), 'test freeze')",
                &[&tenant_id, &format!("org_velocity_{tenant_id}")],
            )
            .await
            .expect("insert frozen tenant");

        clear_freeze(&pool, tenant_id).await.expect("first clear");
        let row = client
            .query_one(
                "SELECT promotion_frozen_at, promotion_frozen_reason FROM tenants WHERE id = $1",
                &[&tenant_id],
            )
            .await
            .expect("read back");
        let frozen_at: Option<chrono::DateTime<chrono::Utc>> = row.get(0);
        assert!(frozen_at.is_none(), "clear must NULL promotion_frozen_at");

        // Clearing an already-clear tenant must not error.
        clear_freeze(&pool, tenant_id)
            .await
            .expect("second clear is idempotent");
    }
}
