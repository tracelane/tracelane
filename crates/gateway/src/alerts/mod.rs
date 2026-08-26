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
//! The 5 metrics: `error_rate` (%), `burn_rate` (× the tenant's per-plan SLO
//! error budget — ADR-020: Team 99% / Business 99.9% / Enterprise 99.95%),
//! `latency_p95` (ms), `cost_usd` (summed over the window), `quota_pct` (% of the
//! monthly trace quota). Comparator is `gt`/`lt` vs a threshold.

pub mod checker;
pub mod routes;

use anyhow::{Context as _, Result, anyhow};
use uuid::Uuid;

use crate::db::DbPool;

/// The alertable metrics. Stored as a validated string (a CHECK constraint
/// backs it); this enum is the parse/label boundary. `overhead_p99` is the
/// gateway-overhead SRE budget (< 15ms) — the mechanical control against the
/// latency-tax regression class (a regression fires instead of hiding).
pub const METRICS: [&str; 6] = [
    "error_rate",
    "burn_rate",
    "latency_p95",
    "overhead_p99",
    "cost_usd",
    "quota_pct",
];

/// Human label + unit suffix for a metric, used in the alert message text.
pub fn metric_label(metric: &str) -> (&'static str, &'static str) {
    match metric {
        "error_rate" => ("error rate", "%"),
        "burn_rate" => ("SLO burn rate", "×"),
        "latency_p95" => ("p95 end-to-end latency", "ms"),
        "overhead_p99" => ("gateway-overhead p99", "ms"),
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

/// Wall-clock bound on the HTTP exchange with a tenant-controlled webhook.
const WEBHOOK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Wall-clock bound on SSRF validation (which does DNS) — `validate_url` has no
/// internal timeout, so without this a slow resolver hangs the synchronous
/// test-fire request until the browser gives up.
const WEBHOOK_VALIDATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Bytes of a webhook's error body we are willing to buffer. A tenant-controlled
/// endpoint can answer with an unbounded stream; we only need the reason string
/// (Slack answers `no_service` / `invalid_token`, Discord a short JSON object).
const MAX_WEBHOOK_BODY_BYTES: usize = 512;
/// Characters of that body we surface back to the tenant / the log.
const MAX_DETAIL_CHARS: usize = 200;

/// Why a webhook delivery did not land.
///
/// The variants are the distinctions a user needs to fix their own destination:
/// `Status` means the webhook answered and said no (a revoked Slack URL answers
/// `404 no_service`) — the case the old fire-and-forget path swallowed entirely,
/// because `reqwest::send()` returns `Ok` for every HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
    /// The URL failed the SSRF guard — nothing left the box.
    Rejected(String),
    /// No HTTP response at all: DNS, TLS, connect, or timeout.
    Unreachable(String),
    /// The webhook answered, and the answer was not 2xx.
    Status { http_status: u16, body: String },
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(m) => write!(f, "webhook URL rejected by the SSRF guard: {m}"),
            Self::Unreachable(m) => write!(f, "webhook unreachable: {m}"),
            // Status + body together is normally a banned shape (a provider error
            // body can echo credentials — .claude/rules/security.md). It is safe
            // here and only here: `body` has already been through
            // `redact::scrub` + a 200-char cap in `sanitize_detail`, and the peer
            // is the tenant's own webhook, not a credentialed provider.
            Self::Status { http_status, body } if body.is_empty() => {
                write!(f, "webhook answered HTTP {http_status}")
            }
            Self::Status { http_status, body } => {
                write!(f, "webhook answered HTTP {http_status}: {body}")
            }
        }
    }
}

impl std::error::Error for DeliveryError {}

/// Scrub, de-control and cap a webhook's response body before it is logged or
/// returned. Credential redaction runs first so a webhook that echoes an
/// `Authorization` header back at us cannot put it in our logs or our API body.
fn sanitize_detail(raw: &[u8]) -> String {
    let scrubbed = tracelane_shared::redact::scrub(raw);
    String::from_utf8_lossy(&scrubbed)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_DETAIL_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Read at most [`MAX_WEBHOOK_BODY_BYTES`] of the response, then sanitize.
/// Chunk-wise rather than `.text()` so a hostile endpoint cannot make us buffer
/// its whole body.
async fn read_bounded_body(resp: reqwest::Response) -> String {
    let mut resp = resp;
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_WEBHOOK_BODY_BYTES);
    while buf.len() < MAX_WEBHOOK_BODY_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = MAX_WEBHOOK_BODY_BYTES - buf.len();
                buf.extend_from_slice(&chunk[..room.min(chunk.len())]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    sanitize_detail(&buf)
}

/// POST a Slack-format `{"text":…}` payload to a tenant-controlled webhook and
/// **assert the outcome**, returning the observed HTTP status on success.
///
/// The URL is validated by the SSRF guard BEFORE any packet leaves the box (a
/// tenant webhook is an SSRF vector); the client is `safe_client_builder`
/// (rustls + no-redirect). Slack, and Discord at `<webhook>/slack`, both accept
/// this exact payload — one path, two providers.
///
/// # Errors
/// **Fail-CLOSED on the report**: this returns `Err` unless the webhook itself
/// answered 2xx. A transport error, an SSRF rejection, and a non-2xx answer are
/// three distinct [`DeliveryError`] variants — none of them is reported as a
/// delivery. (Whether a *caller* then fails open is the caller's choice:
/// [`fire_alert_async`] logs and continues, so a dead webhook never wedges the
/// background checker; the test-fire route surfaces the failure to the user.)
#[tracing::instrument(skip_all, fields(http_status = tracing::field::Empty))]
pub async fn deliver_alert(webhook_url: &str, text: &str) -> Result<u16, DeliveryError> {
    // The webhook URL is itself a credential (a Slack URL embeds its token), so
    // it is never a tracing field and never part of an error string.
    match tokio::time::timeout(
        WEBHOOK_VALIDATE_TIMEOUT,
        crate::ssrf_guard::validate_url(webhook_url),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(DeliveryError::Rejected(e.to_string())),
        Err(_) => {
            return Err(DeliveryError::Unreachable(
                "URL validation (DNS) timed out".to_string(),
            ));
        }
    }

    let client = crate::ssrf_guard::safe_client_builder()
        .timeout(WEBHOOK_TIMEOUT)
        .build()
        .map_err(|e| DeliveryError::Unreachable(format!("HTTP client build failed: {e}")))?;

    let resp = client
        .post(webhook_url)
        .json(&serde_json::json!({ "text": text }))
        .send()
        .await
        .map_err(|e| DeliveryError::Unreachable(e.to_string()))?;

    let http_status = resp.status().as_u16();
    tracing::Span::current().record("http_status", http_status);
    if resp.status().is_success() {
        return Ok(http_status);
    }
    Err(DeliveryError::Status {
        http_status,
        body: read_bounded_body(resp).await,
    })
}

/// Fire-and-forget wrapper over [`deliver_alert`] for the background checker.
///
/// Still fire-and-forget — a breach notification must not block or fail a check
/// tick — but the outcome is now **observed**: a webhook that answers non-2xx
/// produces a `warn` carrying the observed status instead of nothing at all.
pub fn fire_alert_async(webhook_url: String, text: String) {
    tokio::spawn(async move {
        match deliver_alert(&webhook_url, &text).await {
            Ok(http_status) => {
                tracing::debug!(http_status, "alert webhook delivered");
            }
            Err(e) => {
                let observed = match &e {
                    DeliveryError::Status { http_status, .. } => Some(*http_status),
                    _ => None,
                };
                tracing::warn!(
                    error = %e,
                    http_status = observed,
                    "alert webhook delivery FAILED — the notification did not reach the destination"
                );
            }
        }
    });
}

/// Compose the alert message for a breach. Never includes trace contents or key
/// material — only the metric, value, threshold, and window (security #5).
pub fn breach_message(rule: &AlertRule, value: f64) -> String {
    let (label, unit) = metric_label(&rule.metric);
    let cmp = if rule.comparator == "lt" { "<" } else { ">" };
    // quota_pct is cumulative month-to-date — its rule window is ignored (checker.rs
    // `quota_pct`), so "over the last N min" would be a lie. Scope the phrase to the
    // windowed metrics (error_rate / latency_p95 / cost_usd / burn_rate).
    let scope = if rule.metric == "quota_pct" {
        "(month-to-date)".to_string()
    } else {
        format!("over the last {} min", rule.window_minutes)
    };
    format!(
        "🔔 Tracelane alert — {label} is {value:.4}{unit} ({cmp} threshold {:.4}{unit}) \
         {scope}. https://app.tracelane.dev/settings/alerts",
        rule.threshold
    )
}

// See the identical note in `alerts/routes.rs`: these tests drive
// `ssrf_guard::set_loopback_bypass_for_tests`, which only exists under
// `debug_assertions`. `cargo bench` builds test targets with it OFF, so a plain
// `#[cfg(test)]` breaks the Benchmarks job at compile time (E0425).
#[cfg(all(test, debug_assertions))]
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
    fn metrics_list_is_complete() {
        assert_eq!(METRICS.len(), 6);
        assert!(METRICS.contains(&"cost_usd"));
        assert!(METRICS.contains(&"quota_pct"));
        //  prevention: gateway-overhead is a budgetable metric.
        assert!(METRICS.contains(&"overhead_p99"));
    }

    // ── SET-N1: delivery is ASSERTED, not assumed ────────────────────────────
    //
    // The defect these cover: `client.post(..).send().await` returns `Ok` for
    // EVERY HTTP status, so the old notifier treated a revoked Slack webhook
    // (`404 no_service`) exactly like a successful post — silently, forever.

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Wiremock binds 127.0.0.1 and the SSRF guard blocks loopback. Same RAII
    /// thread-local pattern as `providers::smoke_tests` — no process env, so
    /// the parallel suite never races.
    struct LoopbackBypassGuard;
    impl LoopbackBypassGuard {
        fn new() -> Self {
            crate::ssrf_guard::set_loopback_bypass_for_tests(true);
            Self
        }
    }
    impl Drop for LoopbackBypassGuard {
        fn drop(&mut self) {
            crate::ssrf_guard::set_loopback_bypass_for_tests(false);
        }
    }

    async fn mock_webhook(status: u16, body: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
        server
    }

    /// MUST ACCEPT: a webhook that answers 2xx is a delivery, and the observed
    /// status is returned (Slack answers 200, Discord 204).
    #[tokio::test]
    async fn webhook_2xx_is_reported_as_delivered_with_the_observed_status() {
        let _bypass = LoopbackBypassGuard::new();

        let slack = mock_webhook(200, "ok").await;
        assert_eq!(deliver_alert(&slack.uri(), "hello").await, Ok(200));

        let discord = mock_webhook(204, "").await;
        assert_eq!(deliver_alert(&discord.uri(), "hello").await, Ok(204));
    }

    /// MUST REJECT — the regression test for the anchor (`mod.rs:333`, no status
    /// check). A revoked Slack webhook answers `404 no_service`. Before this
    /// change the notifier returned without error and the API said "sent".
    #[tokio::test]
    async fn revoked_webhook_404_is_a_failure_carrying_the_reason() {
        let _bypass = LoopbackBypassGuard::new();
        let server = mock_webhook(404, "no_service").await;

        let out = deliver_alert(&server.uri(), "hello").await;

        assert_eq!(
            out,
            Err(DeliveryError::Status {
                http_status: 404,
                body: "no_service".to_string(),
            }),
            "a 404 from the destination must NOT be reported as a delivery"
        );
        // The reason reaches the user verbatim — that is what makes it fixable.
        let msg = out.unwrap_err().to_string();
        assert!(msg.contains("404"), "{msg}");
        assert!(msg.contains("no_service"), "{msg}");
    }

    /// MUST REJECT: a 5xx from the destination is not a delivery either.
    #[tokio::test]
    async fn webhook_5xx_is_a_failure() {
        let _bypass = LoopbackBypassGuard::new();
        let server = mock_webhook(500, "internal error").await;

        match deliver_alert(&server.uri(), "hello").await {
            Err(DeliveryError::Status { http_status, .. }) => assert_eq!(http_status, 500),
            other => panic!("expected a Status failure, got {other:?}"),
        }
    }

    /// MUST REJECT: an unreachable destination (connection refused) is not a
    /// delivery, and is distinguishable from "the webhook said no".
    #[tokio::test]
    async fn unreachable_webhook_is_not_a_delivery() {
        let _bypass = LoopbackBypassGuard::new();
        // Bind then drop to obtain a port nothing is listening on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let out = deliver_alert(&format!("http://127.0.0.1:{port}/hook"), "hello").await;

        assert!(
            matches!(out, Err(DeliveryError::Unreachable(_))),
            "expected Unreachable, got {out:?}"
        );
    }

    /// MUST REJECT: an SSRF-blocked URL never becomes a delivery. IMDS
    /// (169.254.169.254) is an IP literal in a blocked range, so this holds
    /// regardless of the loopback bypass — no bypass guard here on purpose.
    #[tokio::test]
    async fn ssrf_blocked_url_is_not_a_delivery() {
        let out = deliver_alert("http://169.254.169.254/latest/meta-data", "hello").await;
        assert!(
            matches!(out, Err(DeliveryError::Rejected(_))),
            "expected Rejected, got {out:?}"
        );
    }

    /// The failure detail is bounded and credential-scrubbed before it reaches a
    /// log line or the API body — a hostile destination cannot use our error
    /// path as an echo channel or a memory amplifier.
    #[tokio::test]
    async fn webhook_error_body_is_scrubbed_and_capped() {
        let _bypass = LoopbackBypassGuard::new();
        let hostile = format!(
            "Authorization: Bearer xoxb-unit-test-not-a-real-token\n{}",
            "A".repeat(5000)
        );
        let server = mock_webhook(403, &hostile).await;

        let Err(DeliveryError::Status { body, .. }) = deliver_alert(&server.uri(), "hi").await
        else {
            panic!("expected a Status failure");
        };

        assert!(
            !body.contains("xoxb-unit-test-not-a-real-token"),
            "credential survived redaction: {body}"
        );
        assert!(body.contains("[REDACTED]"), "{body}");
        assert!(
            body.chars().count() <= MAX_DETAIL_CHARS,
            "detail not capped: {} chars",
            body.chars().count()
        );
    }

    #[test]
    fn sanitize_detail_strips_control_characters() {
        assert_eq!(sanitize_detail(b"no\x00_ser\nvice"), "no _ser vice");
    }
}
