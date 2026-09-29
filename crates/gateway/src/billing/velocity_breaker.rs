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
//!
//! **Postgres is contacted only when ClickHouse shows a candidate spike**
//! (NEON-COMPUTE-PIN root cause, 2026-09-19). The first cut read the opt-in
//! key set from Postgres on EVERY tick, before deciding whether any key had
//! tripped — one control-plane query every 300 s, against a Neon compute that
//! suspends after 300 s without one. `pg_stat_statements` on prod: 241 calls
//! of that SELECT in the 20.2 h the compute had been awake, one every 5.04
//! min; the compute had not slept since BILL-01 shipped. The decision is an
//! AND (tripped ∧ enabled), so evaluating the ClickHouse half first and
//! consulting Postgres only for the keys that tripped yields the identical
//! freeze set at zero control-plane cost on a quiet day.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use uuid::Uuid;

use crate::billing::rating::RateCard;

#[derive(serde::Deserialize, clickhouse::Row, Debug, Clone)]
pub struct KeyVelocityRow {
    pub tenant_id: String,
    pub dim: String, // the key id, as a string (meter_counters.dim)
    pub today: f64,
    pub mean_prior: f64,
    pub stddev_prior: f64,
    pub days_of_history: u64,
}

/// B-442 (b): which candidate keys were already checked against `api_keys`, and
/// when. A key that tripped stays a candidate until UTC midnight (today's sum only
/// grows), so without this memo a single spike re-read Postgres EVERY tick for the
/// rest of the day — `pg_stat_statements` on 2026-09-19: `calls` 1 → 9 in 43 min —
/// and a 300 s tick against a 300 s suspend timeout pinned the compute all day.
/// Kept by the spawn loop; pruned to the current candidate set after every tick so
/// it cannot grow past the number of tripped keys.
#[derive(Debug, Default)]
pub struct RecheckMemo {
    checked_at: HashMap<Uuid, std::time::Instant>,
}

impl RecheckMemo {
    /// `true` iff at least one candidate has never been checked, or was last
    /// checked at least `recheck` ago. Pure; no I/O. Empty candidates → `false`.
    #[must_use]
    pub fn needs_postgres(
        &self,
        candidates: &[Candidate],
        now: std::time::Instant,
        recheck: std::time::Duration,
    ) -> bool {
        candidates.iter().any(|c| {
            self.checked_at
                .get(&c.key_id)
                .is_none_or(|t| now.saturating_duration_since(*t) >= recheck)
        })
    }

    /// Record that every current candidate was checked now, and forget keys that
    /// are no longer candidates (they re-enter as fresh if they trip again).
    pub fn mark_checked(&mut self, candidates: &[Candidate], now: std::time::Instant) {
        self.checked_at.clear();
        for c in candidates {
            self.checked_at.insert(c.key_id, now);
        }
    }

    /// Candidates still present but not re-checked this tick keep their stamp;
    /// candidates that vanished are forgotten.
    pub fn retain(&mut self, candidates: &[Candidate]) {
        let live: HashSet<Uuid> = candidates.iter().map(|c| c.key_id).collect();
        self.checked_at.retain(|k, _| live.contains(k));
    }
}

/// One tick: read, decide, write (only on a trip). Never per-key I/O.
///
/// `# Errors`: none returned — every failure is fail-OPEN (a read/write
/// failure here means the breaker misses a tick, never that it blocks
/// promotion by accident; CLAUDE.md §10, a fault-tolerance path).
pub async fn tick(pg: &crate::db::DbPool, ch_url: &str, card: &RateCard, memo: &mut RecheckMemo) {
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
    // The ClickHouse half of the decision FIRST, with no control plane in the
    // loop: which keys tripped today? On a quiet day this is empty and the tick
    // ends here — Postgres is never woken to be told there is nothing to do.
    let candidates = select_candidates(&rows, window_days, sigma);
    if candidates.is_empty() {
        memo.retain(&candidates);
        return;
    }
    // B-442 (b): every candidate was already checked within the recheck window —
    // the opt-in flag is the only thing that could change the answer, and it is
    // re-read at most once per `velocity_recheck_secs`, not once per tick.
    let now = std::time::Instant::now();
    let recheck = std::time::Duration::from_secs(card.policy.velocity_recheck_secs);
    memo.retain(&candidates);
    if !memo.needs_postgres(&candidates, now, recheck) {
        return;
    }

    // ONE Postgres query for the whole opt-in set — never per key, and only
    // now that there is at least one tripped key to check it against.
    let client = match pg.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "velocity breaker: pool unavailable; skipping this tick");
            return;
        }
    };
    let enabled = match enabled_keys(&client).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!(error = %e, "velocity breaker: api_keys read failed; skipping this tick");
            return;
        }
    };
    // Only after a SUCCESSFUL read — a failed one must be retried next tick, not
    // remembered as done (logging.md: never record "done" before the thing is done).
    memo.mark_checked(&candidates, now);

    let to_freeze = freezes_for(candidates, &enabled);
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

/// The same live-key discovery used by the tick and its Postgres proof.
async fn enabled_keys(
    client: &deadpool_postgres::Client,
) -> Result<HashSet<Uuid>, tokio_postgres::Error> {
    let rows = client.query(
        "SELECT id FROM api_keys WHERE velocity_breaker = true AND (revoked_at IS NULL OR revoked_at > now())",
        &[],
    ).await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// One key that exceeded its own trailing threshold today — the ClickHouse
/// half of the decision, before the opt-in filter.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub reason: String,
}

/// The keys that tripped: `days_of_history >= 3` and `today > mean + sigma *
/// stddev` with a finite threshold. Pure; no I/O. Rows whose ids do not parse
/// are skipped, never guessed at.
#[must_use]
pub fn select_candidates(rows: &[KeyVelocityRow], window_days: i64, sigma: f64) -> Vec<Candidate> {
    let mut out = Vec::new();
    for row in rows {
        if row.days_of_history < 3 {
            continue; // not enough signal to call anything a spike
        }
        let threshold = row.mean_prior + sigma * row.stddev_prior;
        if !(threshold.is_finite() && row.today > threshold) {
            continue;
        }
        let (Ok(key_id), Ok(tenant_id)) =
            (Uuid::parse_str(&row.dim), Uuid::parse_str(&row.tenant_id))
        else {
            continue;
        };
        out.push(Candidate {
            key_id,
            tenant_id,
            reason: format!(
                "{key_id}: {:.0} tokens today vs {:.0}\u{b1}{:.0} (trailing {window_days}d)",
                row.today, row.mean_prior, row.stddev_prior
            ),
        });
    }
    out
}

/// Intersect the tripped keys with the opt-in set and dedupe to ONE freeze per
/// tenant per tick, even if several of its keys trip in the same window — "1
/// UPDATE only on a trip", not one per tripped key. The first tripped key's
/// reason is the one recorded.
#[must_use]
pub fn freezes_for(candidates: Vec<Candidate>, enabled: &HashSet<Uuid>) -> HashMap<Uuid, String> {
    let mut to_freeze: HashMap<Uuid, String> = HashMap::new();
    for c in candidates {
        if !enabled.contains(&c.key_id) {
            continue;
        }
        to_freeze.entry(c.tenant_id).or_insert(c.reason);
    }
    to_freeze
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
        let mut memo = RecheckMemo::default();
        loop {
            let interval_secs = card.load().policy.velocity_interval_secs.max(30);
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            tick(&pg, &ch_url, &card.load(), &mut memo).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "11111111-1111-4111-8111-111111111111";
    const KEY_B: &str = "22222222-2222-4222-8222-222222222222";
    const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    fn row(key: &str, today: f64, mean_prior: f64, stddev_prior: f64, days: u64) -> KeyVelocityRow {
        KeyVelocityRow {
            tenant_id: TENANT.to_string(),
            dim: key.to_string(),
            today,
            mean_prior,
            stddev_prior,
            days_of_history: days,
        }
    }

    /// The decision `tick` applies per row — THE function it calls, not a
    /// mirror of it. A mirror would keep passing while `tick` drifted.
    fn trips(today: f64, mean_prior: f64, stddev_prior: f64, days: u64, sigma: f64) -> bool {
        !select_candidates(
            &[row(KEY_A, today, mean_prior, stddev_prior, days)],
            7,
            sigma,
        )
        .is_empty()
    }

    /// B-442 (b), 2026-09-19: on a SPIKE day the same key is a candidate on
    /// every tick until midnight, so the memo — not the empty-candidates early
    /// return — is what keeps Postgres asleep. Fresh → read; all checked within
    /// the window → no read; one stale → read; a candidate that vanished and
    /// returns is fresh again.
    #[test]
    fn a_spike_day_reads_postgres_once_per_recheck_window_not_once_per_tick() {
        use std::time::{Duration, Instant};
        let recheck = Duration::from_secs(3600);
        let t0 = Instant::now();
        let cands = select_candidates(
            &[
                row(KEY_A, 5_000.0, 100.0, 5.0, 7),
                row(KEY_B, 9_000.0, 100.0, 5.0, 7),
            ],
            7,
            2.0,
        );
        assert_eq!(cands.len(), 2, "both keys trip");
        let mut memo = RecheckMemo::default();
        assert!(
            memo.needs_postgres(&cands, t0, recheck),
            "never checked → read"
        );
        memo.mark_checked(&cands, t0);
        // Eleven 300 s ticks later, still inside the hour: NO read.
        assert!(!memo.needs_postgres(&cands, t0 + Duration::from_secs(300 * 11), recheck));
        // The window elapses: read again.
        assert!(memo.needs_postgres(&cands, t0 + recheck, recheck));
        // A third key trips mid-window: read (it is fresh), the others keep their stamp.
        let three = select_candidates(
            &[
                row(KEY_A, 5_000.0, 100.0, 5.0, 7),
                row(KEY_B, 9_000.0, 100.0, 5.0, 7),
                row(
                    "33333333-3333-4333-8333-333333333333",
                    7_000.0,
                    100.0,
                    5.0,
                    7,
                ),
            ],
            7,
            2.0,
        );
        assert!(memo.needs_postgres(&three, t0 + Duration::from_secs(600), recheck));
        // KEY_B stops being a candidate and is forgotten; when it returns it is fresh.
        let only_a = select_candidates(&[row(KEY_A, 5_000.0, 100.0, 5.0, 7)], 7, 2.0);
        memo.retain(&only_a);
        assert!(!memo.needs_postgres(&only_a, t0 + Duration::from_secs(600), recheck));
        assert!(memo.needs_postgres(&cands, t0 + Duration::from_secs(600), recheck));
        // Empty candidates never read, whatever the memo holds.
        assert!(!memo.needs_postgres(&[], t0, recheck));
    }

    /// NEON-COMPUTE-PIN, 2026-09-19: a quiet day must produce NO candidates,
    /// because `tick` returns before `pg.get()` when there are none — that
    /// early return is what keeps a 300 s tick from pinning a Neon compute
    /// whose suspend timeout is 300 s. Ordinary traffic, thin history and a
    /// NaN threshold are all "quiet".
    #[test]
    fn a_quiet_day_yields_no_candidates_so_the_control_plane_is_not_read() {
        let quiet = [
            row(KEY_A, 108.0, 101.14, 6.65, 7),   // inside its own range
            row(KEY_B, 1_000_000.0, 1.0, 0.1, 2), // too little history
            row(KEY_A, 5.0, f64::NAN, 0.0, 7),    // no finite threshold
            row("not-a-uuid", 1_000_000.0, 1.0, 0.1, 7), // unparseable key id
        ];
        assert!(select_candidates(&quiet, 7, 2.0).is_empty());
    }

    /// The opt-in filter and the per-tenant dedupe, applied AFTER the trip
    /// decision, give the same freeze set the old before-the-trip filter did:
    /// a tripped key that is not opted in freezes nothing; two tripped keys of
    /// one tenant freeze it ONCE.
    #[test]
    fn freezes_are_filtered_by_opt_in_and_deduped_per_tenant() {
        let tripped = [
            row(KEY_A, 500.0, 100.0, 5.0, 7),
            row(KEY_B, 900.0, 100.0, 5.0, 7),
        ];
        let cands = select_candidates(&tripped, 7, 2.0);
        assert_eq!(cands.len(), 2, "both keys are over threshold");

        let none: HashSet<Uuid> = HashSet::new();
        assert!(
            freezes_for(cands.clone(), &none).is_empty(),
            "no opt-in, no freeze"
        );

        let only_b: HashSet<Uuid> = [Uuid::parse_str(KEY_B).unwrap()].into_iter().collect();
        let f = freezes_for(cands.clone(), &only_b);
        assert_eq!(f.len(), 1);
        assert!(
            f[&Uuid::parse_str(TENANT).unwrap()].starts_with(KEY_B),
            "the opted-in key's reason"
        );

        let both: HashSet<Uuid> = [KEY_A, KEY_B]
            .iter()
            .map(|k| Uuid::parse_str(k).unwrap())
            .collect();
        assert_eq!(freezes_for(cands, &both).len(), 1, "one tenant, one UPDATE");
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

    #[tokio::test]
    #[ignore = "requires isolated Postgres; POSTGRES_TEST_URL"]
    async fn scheduled_keys_remain_in_breaker_discovery_until_retirement() -> anyhow::Result<()> {
        let config: tokio_postgres::Config = std::env::var("POSTGRES_TEST_URL")?.parse()?;
        let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
        let pool = deadpool_postgres::Pool::builder(manager)
            .max_size(1)
            .build()?;
        let client = pool.get().await?;
        // Temporary table is session-local; the real discovery SQL reads it.
        client.batch_execute("CREATE TEMP TABLE api_keys (id uuid, velocity_breaker boolean, revoked_at timestamptz)").await?;
        let key = Uuid::parse_str(KEY_A)?;
        client
            .execute(
                "INSERT INTO api_keys VALUES ($1, true, now() + interval '1 hour')",
                &[&key],
            )
            .await?;
        let candidates = select_candidates(&[row(KEY_A, 500.0, 100.0, 5.0, 7)], 7, 2.0);
        let enabled = enabled_keys(&client).await?;
        assert!(
            enabled.contains(&key),
            "a key in rotation grace must remain breaker-enabled"
        );
        assert_eq!(freezes_for(candidates.clone(), &enabled).len(), 1);
        client
            .execute("UPDATE api_keys SET revoked_at = now()", &[])
            .await?;
        assert!(freezes_for(candidates.clone(), &enabled_keys(&client).await?).is_empty());
        client
            .execute(
                "UPDATE api_keys SET revoked_at = NULL, velocity_breaker = false",
                &[],
            )
            .await?;
        assert!(enabled_keys(&client).await?.is_empty());
        client
            .execute("UPDATE api_keys SET velocity_breaker = true", &[])
            .await?;
        assert_eq!(
            freezes_for(candidates, &enabled_keys(&client).await?).len(),
            1
        );
        Ok(())
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
