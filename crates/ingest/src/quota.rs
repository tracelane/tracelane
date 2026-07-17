//! Per-tenant ingest quota — the SDK/OTLP-direct cost backstop (ADR-048 D4.2/D5).
//!
//! The gateway `QuotaTracker` counts *gateway requests* and 429s at the hard cap,
//! but spans sent by an SDK or OTLP collector hit the ingest receiver directly
//! and never pass through the gateway — so without this they are unbounded. This
//! is the must-build that closes the bleed on the direct path.
//!
//! - [`QuotaTracker`] holds a per-tenant monthly span counter. When a tenant has
//!   used its cap, the OTLP receiver **hard-rejects with a typed 429** (D5) —
//!   never a silent drop (the #81 failure class). `cap == 0` means *unlimited*
//!   (the default until the Postgres resolver supplies a real per-tenant cap, so
//!   this is non-regressing on a fresh deploy).
//! - [`QuotaNotifier`] sends **one** dedup'd email to the tenant's billing
//!   contact per breach window (1/tenant/24h, never per-span, never to
//!   `support@`). Fire-and-forget — it must never block or fail the 429.
//!
//! The cap is `trace_quota_monthly × overage_hard_cap_multiplier` (5× paid,
//! 99× Enterprise), resolved per-tenant via the `tenant_config`
//! cache and counted in **spans** (the real cost unit ingest sees; the
//! trace-vs-span approximation is documented and conservative — spans ≥ traces).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{Datelike, TimeZone, Utc};
use dashmap::DashMap;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

/// Outcome of a quota check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Within quota — the batch is admitted; `used` is the running monthly total.
    Allowed { used: u64 },
    /// At/over the cap — hard-reject with a 429. `limit` is the cap that was hit.
    Exceeded { used: u64, limit: u64 },
}

/// The current month as `year*100 + month` (e.g. 202606). Quota windows are
/// calendar-monthly (monthly quotas). Wall-clock by design — this is a
/// runtime counter, not a test assertion (tests pass an explicit period).
pub fn current_period() -> u32 {
    let now = Utc::now();
    now.year() as u32 * 100 + now.month()
}

/// First instant of the month after `period`, as an RFC3339 string — the
/// `reset_at` the 429 body advertises so the SDK knows when quota refreshes.
/// Unreachable for a valid `period`, but if chrono ever can't construct the
/// datetime we log and return a manually-formatted (still valid, non-empty)
/// fallback rather than an empty string — the 429 contract always advertises a
/// real reset timestamp.
pub fn reset_at_rfc3339(period: u32) -> String {
    let (y, m) = (period / 100, period % 100);
    let (ny, nm) = if m >= 12 { (y + 1, 1) } else { (y, m + 1) };
    Utc.with_ymd_and_hms(ny as i32, nm, 1, 0, 0, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| {
            tracing::error!(
                period,
                "reset_at_rfc3339: chrono construction failed; manual fallback"
            );
            format!("{ny:04}-{nm:02}-01T00:00:00+00:00")
        })
}

/// Default per-tenant fault quota (ADR-048 / review P1-1): the cap applied while
/// the control-plane resolver is FAULTING (see `tenant_config::fault_keep_all`).
/// Generous — the Enterprise base monthly span count — so a brief blip never
/// rejects a real tenant, but FINITE so a sustained or induced fault hard-stops
/// runaway cost (vs. the old unlimited). Env-tunable via `TRACELANE_FAULT_QUOTA`.
pub const DEFAULT_FAULT_QUOTA: u64 = 25_000_000;

/// Counter for `tracelane_ingest_quota_rejected_total`.
static QUOTA_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Snapshot the quota-reject counter (metrics endpoint / tests).
pub fn rejected_total() -> u64 {
    QUOTA_REJECTED.load(Ordering::Relaxed)
}

/// Per-tenant monthly span counter.
pub struct QuotaTracker {
    // tenant -> (period_yyyymm, spans_used_this_period)
    counters: DashMap<Uuid, (u32, u64)>,
}

impl QuotaTracker {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
        }
    }

    /// Account `n` spans for `tenant` in `period` against `cap`.
    ///
    /// Hard ceiling semantics: if the tenant has already reached `cap`, returns
    /// [`QuotaDecision::Exceeded`] **without** counting (the batch is rejected).
    /// Otherwise the batch is admitted and counted. `cap == 0` ⇒ unlimited. A new
    /// `period` resets the counter (monthly window). The batch that crosses the
    /// cap is admitted; the next one is rejected — so the cap is overshot by at
    /// most one batch, then hard-stops.
    pub fn check_and_add(&self, tenant: Uuid, n: u64, cap: u64, period: u32) -> QuotaDecision {
        let mut e = self.counters.entry(tenant).or_insert((period, 0));
        if e.0 != period {
            *e = (period, 0); // month rolled over → reset
        }
        if cap != 0 && e.1 >= cap {
            QUOTA_REJECTED.fetch_add(1, Ordering::Relaxed);
            return QuotaDecision::Exceeded {
                used: e.1,
                limit: cap,
            };
        }
        e.1 = e.1.saturating_add(n);
        QuotaDecision::Allowed { used: e.1 }
    }

    /// Drop counters from a prior month — bounds the map for a long-running
    /// process (one entry per tenant ever seen; a stale month is dead weight).
    /// The siblings (`TailSampler`/`PerTraceCeiling`) prune by time-age; the
    /// monthly counter prunes by period. Call periodically (see `main`).
    pub fn prune(&self, current_period: u32) {
        self.counters
            .retain(|_, (period, _)| *period == current_period);
    }
}

impl Default for QuotaTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Sends one dedup'd quota-breach email to a tenant's billing contact.
pub struct QuotaNotifier {
    last_sent: DashMap<Uuid, Instant>,
    window: Duration,
    resend_api_key: Option<SecretString>,
    from: String,
    upgrade_url: String,
    http: reqwest::Client,
}

impl QuotaNotifier {
    /// `resend_api_key` / `from` come from env; when the key is absent the
    /// notifier logs loudly instead of emailing (still dedup'd) — honest, never
    /// a silent no-op.
    pub fn new(resend_api_key: Option<SecretString>, from: String, upgrade_url: String) -> Self {
        Self {
            last_sent: DashMap::new(),
            window: Duration::from_secs(24 * 60 * 60),
            resend_api_key,
            from,
            upgrade_url,
            http: reqwest::Client::new(),
        }
    }

    /// True if a notification for `tenant` is allowed now (outside the dedup
    /// window), recording the send. Pure decision — extracted for testing.
    fn should_send_at(&self, tenant: Uuid, now: Instant) -> bool {
        if let Some(prev) = self.last_sent.get(&tenant) {
            if now.saturating_duration_since(*prev) < self.window {
                return false;
            }
        }
        self.last_sent.insert(tenant, now);
        true
    }

    /// Drop dedup entries older than the window — once past it they no longer
    /// suppress, so they are dead weight. Bounds `last_sent` for a long-running
    /// process (mirrors the sampler's `prune_at`). `now` injected for testing.
    pub fn prune_at(&self, now: Instant) {
        let window = self.window;
        self.last_sent
            .retain(|_, last| now.saturating_duration_since(*last) < window);
    }

    /// Convenience over [`prune_at`](Self::prune_at) using the current clock.
    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    /// Fire-and-forget a quota-breach notification. Dedup'd 1/tenant/window.
    /// MUST NOT block or fail the caller (the 429 path). When the Resend key +
    /// billing email are present an email is sent; otherwise a loud structured
    /// log is the notification surface.
    pub fn notify(&self, tenant: Uuid, billing_email: Option<String>, used: u64, limit: u64) {
        if !self.should_send_at(tenant, Instant::now()) {
            return; // already notified this tenant within the dedup window
        }
        match (self.resend_api_key.as_ref(), billing_email) {
            (Some(key), Some(to)) if !to.is_empty() => {
                let body = serde_json::json!({
                    "from": self.from,
                    "to": [to],
                    "subject": "Tracelane: monthly ingest quota reached",
                    "text": format!(
                        "Your workspace reached its monthly trace ingest quota \
                         ({used} of {limit} this month). New spans are being rejected \
                         (HTTP 429) until the quota resets. Upgrade or raise your limit: {url}",
                        url = self.upgrade_url
                    ),
                });
                let http = self.http.clone();
                let auth = format!("Bearer {}", key.expose_secret());
                tokio::spawn(async move {
                    match http
                        .post("https://api.resend.com/emails")
                        .header("authorization", auth)
                        .json(&body)
                        .send()
                        .await
                    {
                        Ok(r) if r.status().is_success() => {
                            tracing::info!(%tenant, "quota-exceeded email sent to billing contact");
                        }
                        // NEVER log the response body — provider errors can echo
                        // the Bearer token (security.md provider-adapter rule).
                        Ok(r) => {
                            tracing::warn!(%tenant, status = %r.status(), "quota email send failed")
                        }
                        Err(_) => tracing::warn!(%tenant, "quota email request errored"),
                    }
                });
            }
            _ => {
                // No Resend key or no billing email yet (default/no-PG path):
                // loud, dedup'd log is the notification surface.
                tracing::warn!(
                    %tenant, used, limit,
                    "monthly ingest quota exceeded — 429ing new spans; billing email NOT sent \
                     (RESEND_API_KEY or billing contact unset)"
                );
            }
        }
    }
}

/// Shared handle alias for the receiver state.
pub type SharedQuotaNotifier = Arc<QuotaNotifier>;

#[cfg(test)]
mod tests {
    use super::*;

    const PERIOD: u32 = 202_606;

    #[test]
    fn allows_under_cap_then_hard_rejects_at_cap() {
        let q = QuotaTracker::new();
        let t = Uuid::from_u128(1);
        // cap 10: a batch of 6 is allowed (used 6), the next 6 crosses (used 12,
        // still admitted), then the third is rejected (used 12 >= 10).
        assert_eq!(
            q.check_and_add(t, 6, 10, PERIOD),
            QuotaDecision::Allowed { used: 6 }
        );
        assert_eq!(
            q.check_and_add(t, 6, 10, PERIOD),
            QuotaDecision::Allowed { used: 12 }
        );
        assert_eq!(
            q.check_and_add(t, 1, 10, PERIOD),
            QuotaDecision::Exceeded {
                used: 12,
                limit: 10
            }
        );
    }

    #[test]
    fn rejects_at_the_cap_not_a_counter() {
        // The eval invariant: a tenant already AT the cap is rejected outright,
        // before any more spans are counted.
        let q = QuotaTracker::new();
        let t = Uuid::from_u128(2);
        assert_eq!(
            q.check_and_add(t, 5, 5, PERIOD),
            QuotaDecision::Allowed { used: 5 }
        );
        assert!(matches!(
            q.check_and_add(t, 1, 5, PERIOD),
            QuotaDecision::Exceeded { .. }
        ));
    }

    #[test]
    fn cap_zero_is_unlimited() {
        let q = QuotaTracker::new();
        let t = Uuid::from_u128(3);
        for _ in 0..1000 {
            assert!(matches!(
                q.check_and_add(t, 1_000_000, 0, PERIOD),
                QuotaDecision::Allowed { .. }
            ));
        }
    }

    #[test]
    fn new_month_resets_the_counter() {
        let q = QuotaTracker::new();
        let t = Uuid::from_u128(4);
        q.check_and_add(t, 10, 10, PERIOD); // used 10
        assert!(matches!(
            q.check_and_add(t, 1, 10, PERIOD),
            QuotaDecision::Exceeded { .. }
        ));
        // Next month → counter resets, batch admitted again.
        assert_eq!(
            q.check_and_add(t, 3, 10, PERIOD + 1),
            QuotaDecision::Allowed { used: 3 }
        );
    }

    #[test]
    fn reject_counter_increments() {
        let q = QuotaTracker::new();
        let t = Uuid::from_u128(5);
        let before = rejected_total();
        q.check_and_add(t, 5, 5, PERIOD);
        q.check_and_add(t, 1, 5, PERIOD); // exceeded
        assert!(rejected_total() > before);
    }

    #[test]
    fn finite_fault_quota_rejects_when_exceeded() {
        // P1-1: a resolver fault applies a FINITE fault quota (DEFAULT_FAULT_QUOTA
        // by default, env-tunable), so a sustained/induced fault still hard-stops.
        // (DEFAULT_FAULT_QUOTA's finiteness is asserted in the tenant_config fault
        // test; here we prove the cap actually rejects when exceeded.)
        let q = QuotaTracker::new();
        let t = Uuid::from_u128(0xFA);
        let fault_cap = 3; // a low fault quota, as the eval sets via env
        assert_eq!(
            q.check_and_add(t, fault_cap, fault_cap, PERIOD),
            QuotaDecision::Allowed { used: fault_cap }
        );
        assert!(
            matches!(
                q.check_and_add(t, 1, fault_cap, PERIOD),
                QuotaDecision::Exceeded { .. }
            ),
            "a tenant past the finite fault quota is rejected, not uncapped"
        );
    }

    #[test]
    fn prune_drops_stale_month_counters() {
        let q = QuotaTracker::new();
        let stale = Uuid::from_u128(0xA1);
        let fresh = Uuid::from_u128(0xA2);
        q.check_and_add(stale, 1, 100, PERIOD); // last month
        q.check_and_add(fresh, 1, 100, PERIOD + 1); // this month
        q.prune(PERIOD + 1);
        assert!(!q.counters.contains_key(&stale), "stale-month entry pruned");
        assert!(q.counters.contains_key(&fresh), "current-month entry kept");
    }

    #[test]
    fn notifier_prune_drops_past_window_entries() {
        let n = QuotaNotifier::new(None, "alerts@tracelane.dev".into(), "https://x/y".into());
        let t = Uuid::from_u128(0xB1);
        let t0 = Instant::now();
        assert!(n.should_send_at(t, t0));
        // As of t0+1h, still within the 24h window → survives prune.
        n.prune_at(t0 + Duration::from_secs(60 * 60));
        assert!(
            n.last_sent.contains_key(&t),
            "in-window entry survives prune"
        );
        // As of t0+25h, past the window → pruned.
        n.prune_at(t0 + Duration::from_secs(25 * 60 * 60));
        assert!(!n.last_sent.contains_key(&t), "past-window entry pruned");
    }

    #[test]
    fn period_rolls_december_to_january() {
        assert_eq!(reset_at_rfc3339(202_612), "2027-01-01T00:00:00+00:00");
        assert_eq!(reset_at_rfc3339(202_606), "2026-07-01T00:00:00+00:00");
    }

    #[test]
    fn notifier_dedups_within_the_window() {
        let n = QuotaNotifier::new(None, "alerts@tracelane.dev".into(), "https://x/y".into());
        let t = Uuid::from_u128(6);
        let t0 = Instant::now();
        assert!(n.should_send_at(t, t0), "first breach notifies");
        assert!(
            !n.should_send_at(t, t0 + Duration::from_secs(60 * 60)),
            "1h later is within the 24h window → suppressed"
        );
        assert!(
            n.should_send_at(t, t0 + Duration::from_secs(25 * 60 * 60)),
            "25h later is outside the window → notifies again"
        );
    }
}
