//! Audit-data retention floor for the Audit add-on SKU (ADR-034).
//!
//! EU AI Act Article 12(2)(c) requires a minimum 6-month retention
//! for high-risk-AI-system logs. The Audit add-on contract promises
//! at least 180 days regardless of the base tier's `retention_days`
//! (free 7d / builder 30d / team 90d / business 180d / enterprise
//! 365d per ADR-020).
//!
//! [`resolve_audit_retention`] is the single source of truth. V1
//! ships the function + the constant; V1.1 wires it into an
//! audit-data cleanup job (no cleanup runs today, so V1 cannot
//! accidentally violate the floor).

/// Hard floor for audit data retention when a workspace has the
/// `f_audit_addon` entitlement. Six months — matches Article 12(2)(c).
/// **Do not** lower this without a new ADR.
pub const AUDIT_ADDON_MIN_RETENTION_DAYS: i32 = 180;

/// Resolve the effective audit-data retention in days for a workspace.
///
/// Precedence:
///   1. `contractual_override` if set — Enterprise-only escape hatch
///      for retention LONGER than the floor (e.g., 7 years for a
///      regulated-industry customer). The override MUST NOT be used
///      to set retention shorter than the floor; the assertion below
///      catches that misuse.
///   2. `max(base_tier_days, AUDIT_ADDON_MIN_RETENTION_DAYS)` when
///      the workspace has the add-on.
///   3. `base_tier_days` otherwise.
///
/// # Panics
///
/// Panics if `contractual_override` is `Some(n)` with `n <
/// AUDIT_ADDON_MIN_RETENTION_DAYS` on an Audit-add-on workspace. The
/// override is structurally intended for "longer than the floor" use
/// cases only. A future caller wanting a *shorter* retention must
/// either (a) not be on the Audit add-on, or (b) get an explicit ADR
/// amendment.
pub fn resolve_audit_retention(
    base_tier_days: i32,
    has_audit_addon: bool,
    contractual_override: Option<i32>,
) -> i32 {
    if let Some(override_days) = contractual_override {
        if has_audit_addon {
            assert!(
                override_days >= AUDIT_ADDON_MIN_RETENTION_DAYS,
                "contractual_override ({override_days}) cannot be shorter than \
                 AUDIT_ADDON_MIN_RETENTION_DAYS ({AUDIT_ADDON_MIN_RETENTION_DAYS}) \
                 for an Audit-add-on workspace"
            );
        }
        return override_days;
    }
    if has_audit_addon {
        return base_tier_days.max(AUDIT_ADDON_MIN_RETENTION_DAYS);
    }
    base_tier_days
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_is_180_days() {
        // Pin the literal so a future "just bump it a little" PR
        // surfaces in code review.
        assert_eq!(AUDIT_ADDON_MIN_RETENTION_DAYS, 180);
    }

    #[test]
    fn audit_addon_lifts_base_tier_to_floor() {
        // Builder (30d) + audit addon → 180d.
        assert_eq!(resolve_audit_retention(30, true, None), 180);
        // Team (90d) + audit addon → 180d.
        assert_eq!(resolve_audit_retention(90, true, None), 180);
        // Business (180d) + audit addon → 180d (already at floor).
        assert_eq!(resolve_audit_retention(180, true, None), 180);
        // Enterprise (365d) + audit addon → 365d (base exceeds floor).
        assert_eq!(resolve_audit_retention(365, true, None), 365);
    }

    #[test]
    fn no_addon_returns_base_tier() {
        assert_eq!(resolve_audit_retention(7, false, None), 7);
        assert_eq!(resolve_audit_retention(30, false, None), 30);
        assert_eq!(resolve_audit_retention(365, false, None), 365);
    }

    #[test]
    fn contractual_override_above_floor_is_honored() {
        // 7-year retention for a regulated customer on Audit addon.
        let seven_years = 7 * 365;
        assert_eq!(
            resolve_audit_retention(365, true, Some(seven_years)),
            seven_years
        );
        // Override also works without the add-on.
        assert_eq!(resolve_audit_retention(30, false, Some(720)), 720);
    }

    #[test]
    #[should_panic(expected = "contractual_override")]
    fn contractual_override_below_floor_with_addon_panics() {
        // 90-day override on an Audit-addon workspace would silently
        // violate Article 12(2)(c). The assert! catches it.
        let _ = resolve_audit_retention(180, true, Some(90));
    }

    #[test]
    fn contractual_override_below_floor_without_addon_is_allowed() {
        // No addon means no Article 12 promise; the override is the
        // operator's call.
        assert_eq!(resolve_audit_retention(180, false, Some(30)), 30);
    }
}
