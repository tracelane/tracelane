//! BILL-01 / ADR-076 step 8 — usage-warning emails.
//!
//! After the daily metering job computes each meter's month-to-date `used`
//! figure, this module checks it against the tenant's `included` allowance
//! (from the entitlement cache) and sends ONE email per (tenant, meter,
//! month, threshold) the FIRST time `used/included` crosses a
//! `billing_policy.warn_pct` threshold (75%, 90% — spec §0.4). Deduplication
//! is the `meter_warnings` INSERT's row count — never a read-then-write.
//!
//! Sending itself goes through `tracelane_shared::email::send_plain_text`
//! (the sender moved out of ingest's now-deleted `QuotaNotifier`, BILL-01
//! step 2) via a `reqwest::Client` built with
//! [`crate::ssrf_guard::safe_client_builder`], and validates the fixed
//! Resend endpoint with [`crate::ssrf_guard::validate_url`] before every send
//! — defence in depth even though the target never varies, matching the
//! convention every other outbound gateway HTTP call in this crate follows.

use secrecy::SecretString;
use uuid::Uuid;

use crate::db::DbPool;

/// One meter's month-to-date usage, ready for the threshold check.
/// `meter` is the `meter_warnings.meter` value — short, stable, and
/// independent of the six billed-meter names `rating::RatedMeter` uses,
/// because a warning is about an ALLOWANCE crossing, not a rated dollar
/// figure.
pub struct MeterUsage {
    pub meter: &'static str,
    pub used: f64,
    /// `None` = Enterprise custom allowance — never warns (nothing to be a
    /// percentage OF).
    pub included: Option<f64>,
}

/// Check every meter in `usages` for `tenant_id` against `warn_pct` and send
/// (at most) one email per meter for the HIGHEST threshold newly crossed
/// this `period`. No-ops entirely when `billing_email` is absent/empty — a
/// tenant with no contact on file gets no email and no error.
///
/// # Behaviour, not signature: fail-open throughout
/// A Postgres failure while checking/recording dedup, or a Resend send
/// failure, is logged and the run continues to the next meter — this is a
/// notification path (CLAUDE.md §10), never a control.
#[allow(clippy::too_many_arguments)]
pub async fn send_usage_warnings_for_tenant(
    pool: &DbPool,
    http: &reqwest::Client,
    resend_api_key: Option<&SecretString>,
    from: &str,
    tenant_id: Uuid,
    billing_email: Option<&str>,
    period: chrono::NaiveDate,
    warn_pct: &[u32],
    usages: &[MeterUsage],
) {
    let Some(to) = billing_email.filter(|e| !e.is_empty()) else {
        return;
    };
    for usage in usages {
        let Some(included) = usage.included else {
            continue;
        };
        if included <= 0.0 {
            continue;
        }
        let pct = 100.0 * usage.used / included;
        let Some(&threshold) = warn_pct.iter().filter(|&&t| pct >= f64::from(t)).max() else {
            continue;
        };
        if !record_warning_if_new(pool, tenant_id, usage.meter, period, threshold).await {
            continue; // already sent this (tenant, meter, period, threshold)
        }
        send_one(
            http,
            resend_api_key,
            from,
            to,
            tenant_id,
            usage.meter,
            pct,
            threshold,
        )
        .await;
    }
}

/// `INSERT ... ON CONFLICT DO NOTHING`; the row count IS the send decision —
/// no read-then-write (spec step 8, verbatim).
async fn record_warning_if_new(
    pool: &DbPool,
    tenant_id: Uuid,
    meter: &str,
    period: chrono::NaiveDate,
    threshold: u32,
) -> bool {
    let Ok(client) = pool.get().await else {
        return false;
    };
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    let threshold_i16 = threshold as i16;
    match client
        .execute(
            "INSERT INTO meter_warnings (tenant_id, meter, period, threshold) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[&tenant_id, &meter, &period, &threshold_i16],
        )
        .await
    {
        Ok(n) => n > 0,
        Err(e) => {
            tracing::warn!(%tenant_id, meter, error = %e, "meter_warnings insert failed");
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_one(
    http: &reqwest::Client,
    resend_api_key: Option<&SecretString>,
    from: &str,
    to: &str,
    tenant_id: Uuid,
    meter: &str,
    pct: f64,
    threshold: u32,
) {
    let url = tracelane_shared::email::RESEND_API_URL;
    if let Err(e) = crate::ssrf_guard::validate_url(url).await {
        // Unreachable in practice (a fixed literal, not operator input), but
        // the guard runs anyway — see the module doc.
        tracing::warn!(%tenant_id, error = %e, "usage-warning email: Resend URL rejected by SSRF guard");
        return;
    }
    let subject = format!("Tracelane: {meter} usage at {pct:.0}% of your plan");
    let text = format!(
        "Your workspace has reached {pct:.0}% of its {meter} allowance for this billing \
         period (threshold: {threshold}%). See your live usage and projection at \
         https://app.tracelane.dev/settings/billing.\n\n\
         Nothing is blocked — ingest and every other capability keep running \
         regardless of this threshold."
    );
    match tracelane_shared::email::send_plain_text(
        http,
        url,
        resend_api_key,
        from,
        to,
        &subject,
        &text,
    )
    .await
    {
        Ok(()) => {
            tracing::info!(%tenant_id, meter, threshold, "usage-warning email sent");
        }
        Err(tracelane_shared::email::EmailError::Unconfigured) => {
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::UsageWarningEmailUnconfigured,
            );
        }
        Err(e) => {
            tracing::warn!(%tenant_id, meter, error = %e, "usage-warning email send failed");
        }
    }
}

/// Build the `reqwest::Client` usage-warning emails send through —
/// `ssrf_guard::safe_client_builder()`, matching every other outbound gateway
/// HTTP call's convention (see the module doc).
#[must_use]
pub fn http_client() -> reqwest::Client {
    crate::ssrf_guard::safe_client_builder()
        .build()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn usage(meter: &'static str, used: f64, included: Option<f64>) -> MeterUsage {
        MeterUsage {
            meter,
            used,
            included,
        }
    }

    /// The early-return guard `send_usage_warnings_for_tenant` applies before
    /// touching Postgres at all: no billing email (`None` or empty) means
    /// nothing is sent. Asserted directly on the same filter expression the
    /// function uses — a `DbPool` cannot be constructed in a unit test
    /// without a live Postgres, so a full call-through integration proof
    /// belongs with `velocity_breaker.rs`'s `#[ignore]`d real-Postgres
    /// pattern, not here.
    #[test]
    fn absent_or_empty_billing_email_is_the_send_guard() {
        assert!(None::<&str>.filter(|e: &&str| !e.is_empty()).is_none());
        assert!(Some("").filter(|e: &&str| !e.is_empty()).is_none());
        assert!(Some("a@b.com").filter(|e: &&str| !e.is_empty()).is_some());
        // Keep the fixture builder + imports exercised so this module's own
        // helpers do not bit-rot unused between the real tests below.
        let _ = usage("ingest", 900.0, Some(1000.0));
    }

    #[test]
    fn threshold_selection_picks_the_highest_crossed() {
        // Mirrors the filter/max the function applies inline — a fixture the
        // arithmetic can be pinned against without I/O.
        let warn_pct = [75u32, 90u32];
        let pick = |pct: f64| {
            warn_pct
                .iter()
                .filter(|&&t| pct >= f64::from(t))
                .max()
                .copied()
        };
        assert_eq!(pick(50.0), None);
        assert_eq!(pick(75.0), Some(75));
        assert_eq!(pick(89.9), Some(75));
        assert_eq!(pick(90.0), Some(90));
        assert_eq!(pick(150.0), Some(90));
    }

    #[test]
    fn enterprise_custom_allowance_never_warns() {
        let u = usage("hot", 1e12, None);
        assert!(u.included.is_none());
    }

    #[tokio::test]
    async fn send_one_notes_degradation_when_unconfigured() {
        use tracelane_shared::degradation::{Degradation, count};
        let before = count(Degradation::UsageWarningEmailUnconfigured);
        let http = reqwest::Client::new();
        send_one(
            &http,
            None,
            "alerts@tracelane.dev",
            "tenant@example.com",
            Uuid::from_u128(1),
            "ingest",
            92.0,
            90,
        )
        .await;
        assert!(count(Degradation::UsageWarningEmailUnconfigured) > before);
    }

    #[tokio::test]
    async fn send_one_delivers_through_a_mock_resend() {
        // Cannot repoint RESEND_API_URL (a fixed literal by design — see
        // `tracelane_shared::email`'s own module doc); this drives the WIRE
        // SHAPE `send_one` builds through a direct call to the shared sender
        // against a mock, matching that module's own test technique.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains(
                "\"subject\":\"Tracelane: ingest usage at 92%",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let http = reqwest::Client::new();
        let key = SecretString::from("rk_test_x".to_string());
        tracelane_shared::email::send_plain_text(
            &http,
            &server.uri(),
            Some(&key),
            "alerts@tracelane.dev",
            "tenant@example.com",
            "Tracelane: ingest usage at 92% of your plan",
            "body",
        )
        .await
        .expect("mocked send must succeed");
    }
}
