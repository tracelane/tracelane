//! User-facing alerting (ADR-059). A tenant defines rules on THEIR OWN metrics
//! → THEIR Slack/Discord webhook. A deterministic background job
//! ([`checker::AlertChecker`]) evaluates enabled rules over the existing
//! ClickHouse span data every tick and fires via the existing SSRF-guarded
//! Slack-format notify path — no LLM/agent on the recovery path (ADR-037).
//!
//! Gated by `f_alerts` (deny-overrides-grant, dark by default). This module owns
//! the Postgres store + the notifier; [`checker`] owns evaluation + firing;
//! [`routes`] owns the CRUD + test-fire API.
//!
//! The 5 metrics: `error_rate` (%), `burn_rate` (× the 99.9% budget),
//! `latency_p95` (ms), `cost_usd` (summed over the window), `quota_pct` (% of the
//! monthly trace quota). Comparator is `gt`/`lt` vs a threshold.

pub mod checker;
pub mod routes;

use anyhow::{Context as _, Result, anyhow};
use uuid::Uuid;

use crate::db::DbPool;

/// The five alertable metrics. Stored as a validated string (a CHECK constraint
/// backs it); this enum is the parse/label boundary.
pub const METRICS: [&str; 5] = [
    "error_rate",
    "burn_rate",
    "latency_p95",
    "cost_usd",
    "quota_pct",
];

/// Human label + unit suffix for a metric, used in the alert message text.
pub fn metric_label(metric: &str) -> (&'static str, &'static str) {
    match metric {
        "error_rate" => ("error rate", "%"),
        "burn_rate" => ("SLO burn rate", "×"),
        "latency_p95" => ("p95 latency", "ms"),
        "cost_usd" => ("cost", " USD"),
        "quota_pct" => ("quota used", "%"),
        _ => ("metric", ""),
    }
}

/// One alert rule row.
#[derive(Debug, Clone)]
pub struct AlertRule {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub metric: String,
    pub comparator: String,
    pub threshold: f64,
    pub window_minutes: i32,
    pub destination_id: Uuid,
    pub enabled: bool,
    pub last_state: String,
}

/// One destination row (a Slack-compatible webhook).
#[derive(Debug, Clone)]
pub struct AlertDestination {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub kind: String,
    pub url: String,
}

/// `true` when `value` breaches `threshold` under `comparator`.
pub fn is_breach(value: f64, comparator: &str, threshold: f64) -> bool {
    match comparator {
        "lt" => value < threshold,
        _ => value > threshold, // "gt" (default)
    }
}

// ── Postgres store ───────────────────────────────────────────────────────────

/// All enabled rules across all tenants, each joined to its destination. Drives
/// the background checker; the checker re-gates each on `f_alerts` so a revoked
/// tenant stops firing without a rules delete.
pub async fn list_enabled_rules_with_dest(
    pool: &DbPool,
) -> Result<Vec<(AlertRule, AlertDestination)>> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    let rows = client
        .query(
            "SELECT r.id, r.tenant_id, r.metric, r.comparator, r.threshold, \
             r.window_minutes, r.destination_id, r.enabled, r.last_state, \
             d.id, d.tenant_id, d.name, d.kind, d.url \
             FROM alert_rules r JOIN alert_destinations d ON d.id = r.destination_id \
             WHERE r.enabled = true",
            &[],
        )
        .await
        .context("SELECT enabled alert_rules failed")?;
    Ok(rows.iter().map(row_to_rule_and_dest).collect())
}

fn row_to_rule_and_dest(row: &tokio_postgres::Row) -> (AlertRule, AlertDestination) {
    (
        AlertRule {
            id: row.get(0),
            tenant_id: row.get(1),
            metric: row.get(2),
            comparator: row.get(3),
            threshold: row.get(4),
            window_minutes: row.get(5),
            destination_id: row.get(6),
            enabled: row.get(7),
            last_state: row.get(8),
        },
        AlertDestination {
            id: row.get(9),
            tenant_id: row.get(10),
            name: row.get(11),
            kind: row.get(12),
            url: row.get(13),
        },
    )
}

/// List a tenant's rules (tenant-scoped — the id comes from validated claims).
pub async fn list_rules(pool: &DbPool, tenant: Uuid) -> Result<Vec<AlertRule>> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    let rows = client
        .query(
            "SELECT id, tenant_id, metric, comparator, threshold, window_minutes, \
             destination_id, enabled, last_state FROM alert_rules \
             WHERE tenant_id = $1 ORDER BY created_at DESC",
            &[&tenant],
        )
        .await
        .context("SELECT alert_rules failed")?;
    Ok(rows
        .iter()
        .map(|r| AlertRule {
            id: r.get(0),
            tenant_id: r.get(1),
            metric: r.get(2),
            comparator: r.get(3),
            threshold: r.get(4),
            window_minutes: r.get(5),
            destination_id: r.get(6),
            enabled: r.get(7),
            last_state: r.get(8),
        })
        .collect())
}

/// Insert a rule for `tenant`, returning its id. The destination must belong to
/// the same tenant (enforced by the caller re-reading it under the tenant id).
#[allow(clippy::too_many_arguments)]
pub async fn create_rule(
    pool: &DbPool,
    tenant: Uuid,
    metric: &str,
    comparator: &str,
    threshold: f64,
    window_minutes: i32,
    destination_id: Uuid,
) -> Result<Uuid> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    let row = client
        .query_one(
            "INSERT INTO alert_rules \
             (tenant_id, metric, comparator, threshold, window_minutes, destination_id) \
             VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
            &[
                &tenant,
                &metric,
                &comparator,
                &threshold,
                &window_minutes,
                &destination_id,
            ],
        )
        .await
        .context("INSERT alert_rules failed")?;
    Ok(row.get(0))
}

/// Delete a rule, tenant-scoped (a foreign tenant id can never match).
pub async fn delete_rule(pool: &DbPool, tenant: Uuid, id: Uuid) -> Result<u64> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    client
        .execute(
            "DELETE FROM alert_rules WHERE id = $1 AND tenant_id = $2",
            &[&id, &tenant],
        )
        .await
        .context("DELETE alert_rules failed")
}

/// Record the outcome of a check: the new state and (when it fired) the fire
/// time. `bumped_fired` is true only when a notification was actually sent.
pub async fn update_rule_state(
    pool: &DbPool,
    id: Uuid,
    state: &str,
    bumped_fired: bool,
) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    if bumped_fired {
        client
            .execute(
                "UPDATE alert_rules SET last_state = $1, last_fired_at = now(), \
                 updated_at = now() WHERE id = $2",
                &[&state, &id],
            )
            .await
            .context("UPDATE alert_rules state+fired failed")?;
    } else {
        client
            .execute(
                "UPDATE alert_rules SET last_state = $1, updated_at = now() WHERE id = $2",
                &[&state, &id],
            )
            .await
            .context("UPDATE alert_rules state failed")?;
    }
    Ok(())
}

/// List a tenant's destinations.
pub async fn list_destinations(pool: &DbPool, tenant: Uuid) -> Result<Vec<AlertDestination>> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    let rows = client
        .query(
            "SELECT id, tenant_id, name, kind, url FROM alert_destinations \
             WHERE tenant_id = $1 ORDER BY created_at DESC",
            &[&tenant],
        )
        .await
        .context("SELECT alert_destinations failed")?;
    Ok(rows
        .iter()
        .map(|r| AlertDestination {
            id: r.get(0),
            tenant_id: r.get(1),
            name: r.get(2),
            kind: r.get(3),
            url: r.get(4),
        })
        .collect())
}

/// Fetch one destination, tenant-scoped (used by test-fire + rule creation).
pub async fn get_destination(
    pool: &DbPool,
    tenant: Uuid,
    id: Uuid,
) -> Result<Option<AlertDestination>> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    let row = client
        .query_opt(
            "SELECT id, tenant_id, name, kind, url FROM alert_destinations \
             WHERE id = $1 AND tenant_id = $2",
            &[&id, &tenant],
        )
        .await
        .context("SELECT alert_destination failed")?;
    Ok(row.map(|r| AlertDestination {
        id: r.get(0),
        tenant_id: r.get(1),
        name: r.get(2),
        kind: r.get(3),
        url: r.get(4),
    }))
}

/// Insert a destination, returning its id.
pub async fn create_destination(
    pool: &DbPool,
    tenant: Uuid,
    name: &str,
    kind: &str,
    url: &str,
) -> Result<Uuid> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    let row = client
        .query_one(
            "INSERT INTO alert_destinations (tenant_id, name, kind, url) \
             VALUES ($1,$2,$3,$4) RETURNING id",
            &[&tenant, &name, &kind, &url],
        )
        .await
        .context("INSERT alert_destinations failed")?;
    Ok(row.get(0))
}

/// Delete a destination, tenant-scoped. `ON DELETE CASCADE` removes its rules.
pub async fn delete_destination(pool: &DbPool, tenant: Uuid, id: Uuid) -> Result<u64> {
    let client = pool.get().await.map_err(|e| anyhow!("alerts pool: {e}"))?;
    client
        .execute(
            "DELETE FROM alert_destinations WHERE id = $1 AND tenant_id = $2",
            &[&id, &tenant],
        )
        .await
        .context("DELETE alert_destinations failed")
}

// ── Notifier (reuses the SSRF-guarded Slack-format path) ─────────────────────

/// Fire-and-forget POST of a Slack-format `{"text":…}` payload to a
/// tenant-controlled webhook. The URL is validated by the SSRF guard BEFORE any
/// packet leaves the box (a tenant webhook is an SSRF vector); the client is
/// `safe_client_builder` (rustls + no-redirect). Slack, and Discord at
/// `<webhook>/slack`, both accept this exact payload — one path, two providers.
pub fn fire_alert_async(webhook_url: String, text: String) {
    tokio::spawn(async move {
        if let Err(e) = crate::ssrf_guard::validate_url(&webhook_url).await {
            tracing::warn!(error = %e, "alert webhook URL rejected by SSRF guard; dropping");
            return;
        }
        let body = serde_json::json!({ "text": text });
        let client = match crate::ssrf_guard::safe_client_builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "alert webhook client build failed");
                return;
            }
        };
        if let Err(e) = client.post(&webhook_url).json(&body).send().await {
            tracing::warn!(error = %e, "alert webhook POST failed");
        }
    });
}

/// Compose the alert message for a breach. Never includes trace contents or key
/// material — only the metric, value, threshold, and window (security #5).
pub fn breach_message(rule: &AlertRule, value: f64) -> String {
    let (label, unit) = metric_label(&rule.metric);
    let cmp = if rule.comparator == "lt" { "<" } else { ">" };
    format!(
        "🔔 Tracelane alert — {label} is {value:.4}{unit} ({cmp} threshold {:.4}{unit}) \
         over the last {} min. https://app.tracelane.dev/settings/alerts",
        rule.threshold, rule.window_minutes
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breach_comparator_semantics() {
        assert!(is_breach(5.0, "gt", 1.0));
        assert!(!is_breach(0.5, "gt", 1.0));
        assert!(is_breach(0.5, "lt", 1.0));
        assert!(!is_breach(5.0, "lt", 1.0));
        // Unknown comparator falls back to gt (the CHECK constraint prevents it,
        // but the evaluator must never panic on a bad row).
        assert!(is_breach(5.0, "??", 1.0));
    }

    #[test]
    fn message_has_no_secret_surface_and_labels_the_metric() {
        let rule = AlertRule {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            metric: "cost_usd".into(),
            comparator: "gt".into(),
            threshold: 1.0,
            window_minutes: 1440,
            destination_id: Uuid::nil(),
            enabled: true,
            last_state: "ok".into(),
        };
        let m = breach_message(&rule, 2.5);
        assert!(m.contains("cost is 2.5000 USD"));
        assert!(m.contains("threshold 1.0000 USD"));
        assert!(m.contains("1440 min"));
        assert!(!m.contains("tlane_"));
    }

    #[test]
    fn metrics_list_is_the_five() {
        assert_eq!(METRICS.len(), 5);
        assert!(METRICS.contains(&"cost_usd"));
        assert!(METRICS.contains(&"quota_pct"));
    }
}
