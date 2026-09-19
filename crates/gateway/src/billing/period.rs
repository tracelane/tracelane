//! B-410 + B-420 (founder ruling, 2026-09-19, verbatim): *"rate everything
//! from current_period_start/end stored on the tenant, never from a calendar
//! month, for every meter including the series meter. Polar stays
//! authoritative on the invoice; the dashboard must agree with Polar, not
//! with a calendar."*
//!
//! This module is the ONE rule for *which window a usage figure is rated
//! over*. `GET /v1/billing/usage` (`usage.rs`), the daily metering job
//! (`metering_job.rs` — the series gauge, the period-to-date counters, the
//! Polar GB-month shares, the usage-warning emails' dedup key and the
//! AUTO-AGE inputs) and its gap backfill all ask it; none carries calendar
//! arithmetic of its own any more, which is how the job and the page stop
//! being able to disagree with each other or with Polar.
//!
//! # The rule
//!
//! A tenant's stored Polar cycle `[current_period_start, current_period_end)`
//! (`tenants.current_period_start/end`, written by the Polar webhook — for an
//! annual tenant it is the $0 monthly USAGE subscription's cycle, BILL-02)
//! governs an instant when the instant lies inside it. Everything else is
//! rated over the UTC calendar month containing the instant:
//!
//! - no cycle stored (Free, or a paid tenant whose subscription webhook has
//!   not delivered one);
//! - a cycle that has ENDED without the renewal webhook landing — stale;
//! - a cycle that has not started yet;
//! - a day being backfilled from before the current cycle began (the
//!   previous cycle's bounds are not stored anywhere).
//!
//! [`BillingPeriod::source`] says which happened. A caller that holds a cycle
//! and gets [`PeriodSource::CalendarMonth`] back is looking at a stale or
//! future cycle and logs it — a renewal webhook that did not arrive is a
//! finding, not a fallback to hide.
//!
//! # Day granularity
//!
//! Every meter is stored per UTC day (`meter_counters.day`,
//! `meter_gauges.day`) and the series read buckets spans by `start_time`, so
//! the window is expressed in whole UTC days: the cycle start's date counts
//! whole, and the cycle end's date belongs to the next cycle. Polar's own
//! clock may split a boundary day at the subscription's time of day; the
//! difference is at most one boundary day per cycle, and every day belongs to
//! exactly one cycle, so nothing is counted twice or dropped.

use chrono::{DateTime, Datelike as _, NaiveDate, Utc};

/// `(current_period_start, current_period_end)` as the entitlement cache and
/// the metering job read them off `tenants`.
pub type Cycle = (DateTime<Utc>, DateTime<Utc>);

/// Which rule produced a [`BillingPeriod`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodSource {
    /// The tenant's stored Polar cycle — the invoice's own window.
    Cycle,
    /// No cycle governs the instant: the UTC calendar month containing it.
    CalendarMonth,
}

/// The window a figure is rated over, in whole UTC days.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingPeriod {
    /// First UTC day inside the window (inclusive).
    pub start: NaiveDate,
    /// First UTC day AFTER the window (exclusive).
    pub end_excl: NaiveDate,
    pub source: PeriodSource,
    /// The governing cycle's own timestamps — what `/v1/billing/usage` sends
    /// as `period_start` / `period_end` so the page can name the cycle.
    /// `None` under the calendar month, INCLUDING the stale-cycle case: a
    /// cycle the figures were not rated over must not be shown beside them.
    pub cycle: Option<Cycle>,
}

/// The window governing `at` for a tenant whose stored cycle is `cycle`.
/// Pure — the instant is a parameter so a 15th-anchored cycle can be tested
/// without a clock.
pub fn billing_period(cycle: Option<Cycle>, at: DateTime<Utc>) -> BillingPeriod {
    if let Some((start, end)) = cycle
        && start < end
        && start <= at
        && at < end
    {
        let (s, e) = (start.date_naive(), end.date_naive());
        // A cycle shorter than one UTC day cannot be a billing cycle; treat it
        // as absent rather than produce a zero-day window.
        if s < e {
            return BillingPeriod {
                start: s,
                end_excl: e,
                source: PeriodSource::Cycle,
                cycle: Some((start, end)),
            };
        }
    }
    calendar_month(at.date_naive())
}

/// The UTC calendar month containing `day` — the fallback, and the only place
/// in the billing tree that spells out "first of the month".
pub fn calendar_month(day: NaiveDate) -> BillingPeriod {
    let start = day.with_day(1).unwrap_or(day);
    let end_excl = if start.month() == 12 {
        NaiveDate::from_ymd_opt(start.year() + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(start.year(), start.month() + 1, 1)
    }
    // `from_ymd_opt(y, m, 1)` is always Some for a valid year; the fallback
    // only exists so no `unwrap` sits outside a test (`.claude/rules/rust.md`).
    .unwrap_or(start);
    BillingPeriod {
        start,
        end_excl,
        source: PeriodSource::CalendarMonth,
        cycle: None,
    }
}

impl BillingPeriod {
    /// Whole days in the window — never 0, so it is safe as a divisor.
    pub fn total_days(&self) -> u32 {
        u32::try_from((self.end_excl - self.start).num_days())
            .unwrap_or(1)
            .max(1)
    }

    /// Days of the window elapsed at `day`, counting `day` itself — the
    /// number of daily figures a period-to-date sum covers. Clamped to
    /// `1..=total_days` so a boundary day (the cycle end's date, which the
    /// instant test may still assign to this cycle) never projects past 100%.
    pub fn elapsed_days(&self, day: NaiveDate) -> u32 {
        let total = i64::from(self.total_days());
        let elapsed = (day - self.start).num_days() + 1;
        u32::try_from(elapsed.clamp(1, total)).unwrap_or(1)
    }

    /// `(elapsed_days, total_days)` as `f64` — the linear-projection input
    /// every meter but hot uses (`used / elapsed × total`).
    pub fn progress(&self, day: NaiveDate) -> (f64, f64) {
        (
            f64::from(self.elapsed_days(day)),
            f64::from(self.total_days()),
        )
    }

    /// `true` when a stored cycle exists but did not govern — stale (ended
    /// without a renewal webhook) or not yet started. The caller logs it.
    pub fn ignored_cycle(&self, stored: Option<Cycle>) -> bool {
        stored.is_some() && self.source == PeriodSource::CalendarMonth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: u32, d: u32, h: u32) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(y, m, d)
                .unwrap()
                .and_hms_opt(h, 0, 0)
                .unwrap(),
            Utc,
        )
    }

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    /// The B-420 shape: a cycle anchored on the 15th spans two partial
    /// calendar months. Read on the 3rd of the second month, the window
    /// starts on the 15th of the first — not on the 1st of either.
    #[test]
    fn a_cycle_starting_on_the_15th_governs_across_the_month_boundary() {
        let cycle = Some((at(2026, 9, 15, 0), at(2026, 10, 15, 0)));
        let p = billing_period(cycle, at(2026, 10, 3, 4));
        assert_eq!(p.source, PeriodSource::Cycle);
        assert_eq!(p.start, day(2026, 9, 15));
        assert_eq!(p.end_excl, day(2026, 10, 15));
        assert_eq!(p.total_days(), 30);
        // 09-15 .. 10-03 inclusive = 19 daily figures.
        assert_eq!(p.elapsed_days(day(2026, 10, 3)), 19);
        assert_eq!(p.progress(day(2026, 10, 3)), (19.0, 30.0));
        assert_eq!(p.cycle, cycle);
        assert!(!p.ignored_cycle(cycle));
    }

    #[test]
    fn no_cycle_falls_back_to_the_calendar_month() {
        let p = billing_period(None, at(2026, 10, 3, 4));
        assert_eq!(p.source, PeriodSource::CalendarMonth);
        assert_eq!(p.start, day(2026, 10, 1));
        assert_eq!(p.end_excl, day(2026, 11, 1));
        assert_eq!(p.total_days(), 31);
        assert_eq!(p.elapsed_days(day(2026, 10, 3)), 3);
        assert_eq!(p.cycle, None);
        assert!(!p.ignored_cycle(None));
    }

    #[test]
    fn december_rolls_into_january_and_february_counts_its_own_days() {
        let dec = calendar_month(day(2026, 12, 25));
        assert_eq!(dec.end_excl, day(2027, 1, 1));
        assert_eq!(dec.total_days(), 31);
        assert_eq!(calendar_month(day(2024, 2, 10)).total_days(), 29);
        assert_eq!(calendar_month(day(2026, 2, 10)).total_days(), 28);
    }

    /// A cycle that ENDED without the renewal webhook landing is not the
    /// current cycle; rating from its start would fold a whole previous cycle
    /// into "period to date". The calendar month governs, the cycle is not
    /// echoed back for display, and the caller can see it was ignored.
    #[test]
    fn a_stale_cycle_is_ignored_and_reported() {
        let cycle = Some((at(2026, 8, 15, 0), at(2026, 9, 15, 0)));
        let p = billing_period(cycle, at(2026, 10, 3, 4));
        assert_eq!(p.source, PeriodSource::CalendarMonth);
        assert_eq!(p.start, day(2026, 10, 1));
        assert_eq!(
            p.cycle, None,
            "a cycle the figures were not rated over is not shown"
        );
        assert!(p.ignored_cycle(cycle));
    }

    #[test]
    fn a_cycle_that_has_not_started_is_ignored_too() {
        let cycle = Some((at(2026, 11, 15, 0), at(2026, 12, 15, 0)));
        let p = billing_period(cycle, at(2026, 10, 3, 4));
        assert_eq!(p.source, PeriodSource::CalendarMonth);
        assert!(p.ignored_cycle(cycle));
    }

    /// The renewal day, before the webhook: the instant is still inside the
    /// old cycle by Polar's clock (end 13:22, read at 04:10), so the old
    /// cycle governs; elapsed clamps to the window rather than projecting
    /// a 31st day of a 30-day cycle.
    #[test]
    fn the_end_date_before_the_end_time_still_belongs_to_the_old_cycle() {
        let cycle = Some((at(2026, 9, 14, 13), at(2026, 10, 14, 13)));
        let p = billing_period(cycle, at(2026, 10, 14, 4));
        assert_eq!(p.source, PeriodSource::Cycle);
        assert_eq!(p.start, day(2026, 9, 14));
        assert_eq!(p.total_days(), 30);
        assert_eq!(p.elapsed_days(day(2026, 10, 14)), 30);
        // …and once the instant passes the end time, the stored cycle is stale.
        assert!(billing_period(cycle, at(2026, 10, 14, 14)).ignored_cycle(cycle));
    }

    #[test]
    fn a_reversed_or_sub_day_cycle_is_treated_as_absent() {
        let reversed = Some((at(2026, 10, 15, 0), at(2026, 9, 15, 0)));
        assert_eq!(
            billing_period(reversed, at(2026, 10, 3, 4)).source,
            PeriodSource::CalendarMonth
        );
        let sub_day = Some((at(2026, 10, 3, 1), at(2026, 10, 3, 6)));
        assert_eq!(
            billing_period(sub_day, at(2026, 10, 3, 4)).source,
            PeriodSource::CalendarMonth
        );
    }

    #[test]
    fn elapsed_never_drops_below_one_day() {
        let cycle = Some((at(2026, 9, 15, 0), at(2026, 10, 15, 0)));
        let p = billing_period(cycle, at(2026, 9, 15, 4));
        assert_eq!(p.elapsed_days(day(2026, 9, 15)), 1);
        // A day before the start (a caller mixing windows) still divides safely.
        assert_eq!(p.elapsed_days(day(2026, 9, 1)), 1);
    }
}
