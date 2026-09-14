//! Per-key budget reset cadence (BILL-01 A3) and its window-key arithmetic.
//!
//! Lives in `tracelane-shared`, not `gateway::spend`, because
//! `crates/gateway/src/db/api_keys.rs` is compiled a SECOND time as a
//! standalone module inside `tests/postgres_tenant_integration.rs` (via
//! `#[path = "../src/db/mod.rs"]`) — a separate crate that has
//! `tracelane_shared` as a normal dependency but no access to `gateway`'s own
//! internal `crate::spend` module. A type referenced from `db::api_keys`
//! that needs to compile in both places has to live somewhere both can reach
//! without either one growing extra `#[path]` mounts — `tracelane-shared` is
//! that place, the same reason `TenantId` lives here rather than in the
//! gateway crate.

use chrono::{DateTime, Utc};

/// A per-key budget's reset cadence (`api_keys.budget_reset`, migration
/// 0040). `Monthly` is the pre-A3 default and the only cadence a key minted
/// before this column existed can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetReset {
    Daily,
    Weekly,
    Monthly,
}

impl BudgetReset {
    /// Parse the Postgres `text` value (`CHECK`-constrained to these three).
    /// Anything unrecognised falls back to `Monthly` — the widest window, so
    /// an unparseable cadence never makes a key's ceiling STRICTER than
    /// configured (a customer's own opt-in ceiling, not a security path;
    /// `CLAUDE.md` §10's fault-tolerance direction applies).
    #[must_use]
    pub fn from_column(s: &str) -> Self {
        match s {
            "daily" => Self::Daily,
            "weekly" => Self::Weekly,
            _ => Self::Monthly,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }
}

/// `YYYYMM` for a UTC instant — the monthly period key.
#[must_use]
pub fn year_month(now: DateTime<Utc>) -> u32 {
    use chrono::Datelike as _;
    now.year() as u32 * 100 + now.month()
}

/// The spend-tracker window key for `cadence` at `now`. `Monthly` is exactly
/// [`year_month`]; `Daily` is `YYYYMMDD`; `Weekly` is ISO year × 100 + ISO
/// week number (Monday-start, ISO 8601) — three cadences, one opaque `u32`
/// key, so a `(subject, period)`-keyed tracker needs no API change at all:
/// only what the CALLER computes for that integer differs.
#[must_use]
pub fn window_key(cadence: BudgetReset, now: DateTime<Utc>) -> u32 {
    use chrono::Datelike as _;
    match cadence {
        BudgetReset::Monthly => year_month(now),
        BudgetReset::Daily => now.year() as u32 * 10_000 + now.month() * 100 + now.day(),
        BudgetReset::Weekly => {
            let iso = now.iso_week();
            iso.year() as u32 * 100 + iso.week()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn budget_reset_parses_the_three_check_constrained_values() {
        assert_eq!(BudgetReset::from_column("daily"), BudgetReset::Daily);
        assert_eq!(BudgetReset::from_column("weekly"), BudgetReset::Weekly);
        assert_eq!(BudgetReset::from_column("monthly"), BudgetReset::Monthly);
        assert_eq!(
            BudgetReset::from_column("garbage"),
            BudgetReset::Monthly,
            "an unparseable cadence must widen, never narrow, the window"
        );
    }

    #[test]
    fn as_str_round_trips_from_column() {
        for r in [
            BudgetReset::Daily,
            BudgetReset::Weekly,
            BudgetReset::Monthly,
        ] {
            assert_eq!(BudgetReset::from_column(r.as_str()), r);
        }
    }

    #[test]
    fn year_month_is_yyyymm() {
        assert_eq!(year_month(dt("2026-09-13T00:00:00Z")), 202_609);
        assert_eq!(year_month(dt("2026-01-01T00:00:00Z")), 202_601);
        assert_eq!(year_month(dt("2026-12-31T23:59:59Z")), 202_612);
    }

    #[test]
    fn window_key_monthly_matches_year_month_exactly() {
        let now = dt("2026-09-13T12:00:00Z");
        assert_eq!(window_key(BudgetReset::Monthly, now), year_month(now));
    }

    #[test]
    fn window_key_daily_is_yyyymmdd() {
        assert_eq!(
            window_key(BudgetReset::Daily, dt("2026-09-13T00:00:00Z")),
            20_260_913
        );
        // A UTC day boundary — 23:59:59 and 00:00:00 the next day must differ.
        assert_eq!(
            window_key(BudgetReset::Daily, dt("2026-09-13T23:59:59Z")),
            20_260_913
        );
        assert_eq!(
            window_key(BudgetReset::Daily, dt("2026-09-14T00:00:00Z")),
            20_260_914
        );
    }

    #[test]
    fn window_key_weekly_resets_on_the_iso_monday_boundary() {
        // 2026-09-13 is a Sunday (ISO week ends Sunday 23:59:59); the next day,
        // Monday 2026-09-14, starts a new ISO week.
        let sunday = dt("2026-09-13T23:59:59Z");
        let monday = dt("2026-09-14T00:00:00Z");
        assert_ne!(
            window_key(BudgetReset::Weekly, sunday),
            window_key(BudgetReset::Weekly, monday),
            "the ISO week must roll at the Monday boundary, not at a calendar-week one"
        );
    }

    #[test]
    fn window_key_weekly_handles_the_iso_year_boundary() {
        // 2026-01-01 is a Thursday, so ISO week 1 of 2026 actually started
        // 2025-12-29 — the ISO year and the calendar year disagree here, which
        // is exactly the case a naive `now.year()` would get wrong.
        let key = window_key(BudgetReset::Weekly, dt("2026-01-01T00:00:00Z"));
        let (iso_year, iso_week) = (key / 100, key % 100);
        assert_eq!(iso_year, 2026);
        assert_eq!(iso_week, 1);
    }
}
