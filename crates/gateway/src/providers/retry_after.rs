//! `OG-10` — the upstream `Retry-After` header, parsed once for every adapter.
//!
//! RFC 9110 §10.2.3: the value is either `delay-seconds` (a non-negative decimal
//! integer) or an `HTTP-date`. The date has three legal spellings a recipient MUST
//! accept (RFC 9110 §5.6.7): IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), the
//! obsolete RFC 850 form (`Sunday, 06-Nov-94 08:49:37 GMT`) and ANSI C `asctime()`
//! (`Sun Nov  6 08:49:37 1994`). All three are read, as UTC.
//!
//! **A fractional delay (`0.1`) is also accepted.** It is not RFC-legal, but a
//! provider that sends it plainly means "a tenth of a second", and refusing it would
//! turn that into a jittered guess. Anything else — a sign, an exponent, text — is
//! garbage and yields `None`, which the retry loop reads as "no hint".
//!
//! The ceiling is a reference-table value (`translation_policy.v1.json`
//! `limits.retry_after_max_secs`, CLAUDE.md §23), not a literal here. **Fail
//! direction:** an unparseable table gives a ceiling of 0, and a ceiling of 0 means
//! "ignore the header" (`None`) — the loop then falls back to its own jittered
//! backoff, never to a wait the provider did not ask for and we cannot bound.

use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};

/// Parse a `Retry-After` value against `now`, clamped to `max`.
///
/// A date in the past is `0`; a delay or date beyond `max` is `max`.
/// `None` for garbage, and for a `max` of zero (see the module doc).
#[must_use]
pub(crate) fn parse_retry_after(
    value: &str,
    now: DateTime<Utc>,
    max: Duration,
) -> Option<Duration> {
    if max.is_zero() {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let wait = if let Some(secs) = parse_delay_seconds(value) {
        secs
    } else {
        let at = parse_http_date(value)?;
        // `to_std` errs on a negative span: a past date means "now", i.e. 0.
        (at - now).to_std().unwrap_or(Duration::ZERO)
    };
    Some(wait.min(max))
}

/// `delay-seconds`, with an optional `.fraction`. Digits only: no sign, no exponent.
fn parse_delay_seconds(v: &str) -> Option<Duration> {
    let (whole, frac) = match v.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (v, None),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if frac.is_some_and(|f| f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    // A value too large for u64 is still "a huge value": saturate and let the clamp win.
    let secs = whole.parse::<u64>().unwrap_or(u64::MAX);
    let frac_secs = frac
        .and_then(|f| format!("0.{f}").parse::<f64>().ok())
        .unwrap_or(0.0);
    // L3 (security review 2026-10-02): the header is provider-controlled, so the sum must
    // never panic. A fraction can round to 1.0 and carry a whole second onto `u64::MAX`;
    // saturate — the caller's clamp then wins.
    Some(
        Duration::from_secs(secs)
            .saturating_add(Duration::from_secs_f64(frac_secs.clamp(0.0, 1.0))),
    )
}

fn parse_http_date(v: &str) -> Option<DateTime<Utc>> {
    // IMF-fixdate. chrono's RFC 2822 reader accepts the `GMT` zone.
    if let Ok(d) = DateTime::parse_from_rfc2822(v) {
        return Some(d.with_timezone(&Utc));
    }
    // Obsolete RFC 850 and asctime, both defined as GMT.
    let v = v.strip_suffix(" GMT").unwrap_or(v);
    for fmt in ["%A, %d-%b-%y %H:%M:%S", "%a %b %e %H:%M:%S %Y"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(v, fmt) {
            return Some(n.and_utc());
        }
    }
    None
}

/// The upstream's `Retry-After`, read from a response's headers — call it in every
/// adapter's non-success branch BEFORE the body is read.
///
/// `None` when the header is absent, is not valid ASCII, or is garbage.
#[must_use]
pub fn retry_after_from(headers: &axum::http::HeaderMap) -> Option<Duration> {
    // reqwest and axum share the `http` crate's types.
    let raw = headers
        .get(axum::http::header::RETRY_AFTER)?
        .to_str()
        .ok()?;
    let max = Duration::from_secs(super::translation_policy::limits().retry_after_max_secs);
    parse_retry_after(raw, Utc::now(), max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    const MAX: Duration = Duration::from_secs(3600);

    fn now() -> DateTime<Utc> {
        // 1994-11-06 08:49:37 UTC, the RFC's own example instant.
        Utc.with_ymd_and_hms(1994, 11, 6, 8, 49, 37).unwrap()
    }

    #[test]
    fn seconds_parse_and_a_fraction_is_honoured() {
        assert_eq!(
            parse_retry_after("20", now(), MAX),
            Some(Duration::from_secs(20))
        );
        assert_eq!(parse_retry_after("0", now(), MAX), Some(Duration::ZERO));
        assert_eq!(
            parse_retry_after(" 7 ", now(), MAX),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            parse_retry_after("0.1", now(), MAX),
            Some(Duration::from_millis(100))
        );
    }

    /// L3 (security review 2026-10-02): a provider-controlled header must never panic the
    /// gateway. `u64::MAX` seconds plus a fraction overflowed `Duration`'s `Add`.
    #[test]
    fn l3_a_huge_value_with_a_fraction_saturates_to_the_ceiling_instead_of_panicking() {
        assert_eq!(
            parse_retry_after("99999999999999999999.5", now(), MAX),
            Some(MAX)
        );
        assert_eq!(
            parse_retry_after("18446744073709551615.999", now(), MAX),
            Some(MAX)
        );
        // A fraction that rounds to 1.0 in f64 carries a whole second onto u64::MAX.
        assert_eq!(
            parse_retry_after("99999999999999999999.99999999999999999999", now(), MAX),
            Some(MAX)
        );
    }

    #[test]
    fn an_http_date_is_a_delay_from_now_in_all_three_spellings() {
        for d in [
            "Sun, 06 Nov 1994 08:50:37 GMT",
            "Sunday, 06-Nov-94 08:50:37 GMT",
            "Sun Nov  6 08:50:37 1994",
        ] {
            assert_eq!(
                parse_retry_after(d, now(), MAX),
                Some(Duration::from_secs(60)),
                "{d}"
            );
        }
    }

    #[test]
    fn a_past_date_is_zero_not_none() {
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:00:00 GMT", now(), MAX),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn garbage_is_none() {
        for g in [
            "",
            "   ",
            "soon",
            "-5",
            "+5",
            "1e3",
            "1.",
            ".5",
            "1.2.3",
            "NaN",
            "inf",
            "5s",
            "Sun, 99 Nov 1994 08:50:37 GMT",
        ] {
            assert_eq!(parse_retry_after(g, now(), MAX), None, "{g:?}");
        }
    }

    #[test]
    fn a_huge_value_is_clamped_not_rejected() {
        assert_eq!(parse_retry_after("999999", now(), MAX), Some(MAX));
        assert_eq!(
            parse_retry_after("99999999999999999999999999", now(), MAX),
            Some(MAX)
        );
        assert_eq!(
            parse_retry_after("Fri, 31 Dec 9999 23:59:59 GMT", now(), MAX),
            Some(MAX)
        );
    }

    #[test]
    fn a_zero_ceiling_ignores_the_header() {
        // The fail direction of an unparseable policy table.
        assert_eq!(parse_retry_after("20", now(), Duration::ZERO), None);
    }

    #[test]
    fn the_header_reader_uses_the_table_ceiling() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("20"),
        );
        assert_eq!(retry_after_from(&h), Some(Duration::from_secs(20)));
        h.insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("86400"),
        );
        assert_eq!(
            retry_after_from(&h),
            Some(Duration::from_secs(
                super::super::translation_policy::limits().retry_after_max_secs
            ))
        );
        assert_eq!(retry_after_from(&axum::http::HeaderMap::new()), None);
    }
}
