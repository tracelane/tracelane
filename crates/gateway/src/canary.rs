//!
//! Progressive delivery for prompt/config changes: a candidate rolls to a small
//! cohort of tenants for a **detection bake** before fleet-wide promotion. The
//! cohort is selected *deterministically* from the tenant id so a given tenant
//! is consistently in or out across requests (no flapping) and the split is
//! reproducible without shared state.
//!
//! Whether a canary is active for a feature is gated by the operational flag
//! `flag.canary.<feature>` (see [`crate::kill_switch::KillSwitch::canary_enabled`]);
//! this module decides *which* tenants are in the cohort once it is active.
//!
//! These are complete, unit-tested primitives. They have no V1 call site yet:
//! the consumer is a staged gateway-config rollout, which has no candidate
//! config to route to until the first progressive deploy uses it (ADR-038
//! §23.5). `dead_code` is allowed here for that reason, not because the logic
//! is incomplete — `should_route_to_canary` is the single entry point.
#![allow(dead_code)]

use uuid::Uuid;

use crate::kill_switch::KillSwitch;

/// Hard ceiling on canary traffic share (ADR-038 §23.5): a candidate holds at
/// **≤5%** of tenants during the bake before fleet-wide promotion.
pub const MAX_CANARY_PERCENT: u8 = 5;

/// Detection-bake = this multiple of the p99 detection latency. A candidate
/// must hold the canary cohort for at least `DETECTION_BAKE_MULTIPLIER × p99`
/// before promotion, so a regression surfaces inside the bake window
/// (release-vs-detection invariant, §23.4).
pub const DETECTION_BAKE_MULTIPLIER: u32 = 10;

/// Is `tenant` in the canary cohort at `percent` traffic share?
///
/// Deterministic: derived from the tenant uuid, so the same tenant is stably
/// in/out. `percent` is clamped to [`MAX_CANARY_PERCENT`] — a caller cannot
/// accidentally roll a canary past the 5% ceiling.
pub fn in_canary_cohort(tenant: Uuid, percent: u8) -> bool {
    let pct = u128::from(percent.min(MAX_CANARY_PERCENT));
    if pct == 0 {
        return false;
    }
    // Uniform bucket in [0, 100) from the uuid; in-cohort when bucket < pct.
    (tenant.as_u128() % 100) < pct
}

/// The minimum bake duration for a given measured p99 detection latency.
pub fn detection_bake(p99_detection: std::time::Duration) -> std::time::Duration {
    p99_detection * DETECTION_BAKE_MULTIPLIER
}

/// Single entry point for a config canary: the candidate is served to `tenant`
/// only when the operational flag `flag.canary.<feature>` is on AND the tenant
/// falls in the ≤5% cohort. Combines the operational gate (ADR-038 §23.6) with
/// the deterministic cohort (§23.5).
pub fn should_route_to_canary(
    kill_switch: &KillSwitch,
    tenant: Uuid,
    feature: &str,
    percent: u8,
) -> bool {
    kill_switch.canary_enabled(feature) && in_canary_cohort(tenant, percent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_is_capped_at_five() {
        // Even asking for 100% never exceeds the 5% ceiling: a tenant in
        // bucket >= 5 is out regardless of the requested percent.
        let out_tenant = Uuid::from_u128(7); // bucket 7
        assert!(!in_canary_cohort(out_tenant, 100));
        let in_tenant = Uuid::from_u128(3); // bucket 3 < 5
        assert!(in_canary_cohort(in_tenant, 100));
    }

    #[test]
    fn zero_percent_excludes_everyone() {
        assert!(!in_canary_cohort(Uuid::from_u128(1), 0));
    }

    #[test]
    fn deterministic_for_a_tenant() {
        let t = Uuid::from_u128(2);
        assert_eq!(in_canary_cohort(t, 5), in_canary_cohort(t, 5));
    }

    #[test]
    fn roughly_five_percent_in_cohort() {
        let mut hits = 0u32;
        for i in 0..10_000u128 {
            if in_canary_cohort(Uuid::from_u128(i), 5) {
                hits += 1;
            }
        }
        // 5% of 10K = 500; uuid-from-counter is uniform mod 100 → exactly 500.
        assert_eq!(hits, 500);
    }

    #[test]
    fn detection_bake_is_ten_x() {
        let bake = detection_bake(std::time::Duration::from_millis(50));
        assert_eq!(bake, std::time::Duration::from_millis(500));
    }
}
