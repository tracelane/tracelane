//! The `Rail` trait + entitlement-gate abstraction (the guardrail spec
//! §2.6, §2.7). A rail is a pure evaluation over [`GuardrailContext`] returning
//! `Result<RailOutcome, RailError>`; it performs no network/disk I/O on the hot
//! path (only in-memory/cached reads).
//!
//! Object safety: rails live in a `Vec<Box<dyn Rail>>`, so `evaluate` returns a
//! boxed future (the established pattern from `crate::predictive::Predictor`,
//! NOT the banned `async-trait` macro and NOT RPITIT — neither is
//! dyn-compatible here). For V1 every rail is synchronous CPU work, so the
//! future resolves immediately; the boxing is one tiny alloc per rail per side,
//! well inside the 5ms p99 budget, and future-proofs a rail that needs a cached
//! async read.
//!
//! Gating: each rail declares the [`GuardrailFeature`] that gates it, or `None`
//! for a free-tier default (R1, R3 schema-val, R8 heuristic — §2.7). The
//! dispatcher consults a pre-resolved [`RailGate`] (booleans resolved from
//! `workspace_entitlements` once per request, off the hot path) so the gating
//! check itself is a synchronous bitset lookup.

use std::future::Future;
use std::pin::Pin;

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::outcome::{FailMode, RailError, RailOutcome, Sides};

/// The entitlement flag that gates a rail (§2.7). Free-tier defaults have no
/// flag — they are always on. Resolution to a `workspace_entitlements` row
/// lands in P0.6 (`guardrail::entitlement`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardrailFeature {
    /// R2 secrets + structured-PII redaction.
    R2SecretsPii,
    /// R3 tool definition-pinning (the schema-validation half is free).
    R3DefinitionPinning,
    /// R4 lethal-trifecta taint tracking (flagship).
    R4Trifecta,
    /// R5 output format / schema enforcement.
    R5Format,
    /// R6 system-prompt-leak detection.
    R6SysPromptLeak,
    /// R7 topic / competitor blocklist.
    R7TopicCompetitor,
}

impl GuardrailFeature {
    /// All gated features (the non-free-default rails). Used by [`RailGate::all`].
    pub const ALL: [GuardrailFeature; 6] = [
        GuardrailFeature::R2SecretsPii,
        GuardrailFeature::R3DefinitionPinning,
        GuardrailFeature::R4Trifecta,
        GuardrailFeature::R5Format,
        GuardrailFeature::R6SysPromptLeak,
        GuardrailFeature::R7TopicCompetitor,
    ];
}

/// A pre-resolved set of granted rail features for one request (§2.7). Built
/// from `workspace_entitlements` once per request (P0.6) and passed to the
/// dispatcher so per-rail gating is a synchronous lookup. A rail whose
/// `feature()` is `None` is always allowed (free default).
#[derive(Debug, Clone, Default)]
pub struct RailGate {
    granted: u8,
}

impl RailGate {
    /// Nothing granted beyond the free-tier defaults.
    #[must_use]
    pub fn free_defaults_only() -> Self {
        Self { granted: 0 }
    }

    /// Everything granted — Enterprise / tests.
    #[must_use]
    pub fn all() -> Self {
        let mut g = Self::free_defaults_only();
        for f in GuardrailFeature::ALL {
            g = g.grant(f);
        }
        g
    }

    fn bit(feature: GuardrailFeature) -> u8 {
        match feature {
            GuardrailFeature::R2SecretsPii => 1 << 0,
            GuardrailFeature::R3DefinitionPinning => 1 << 1,
            GuardrailFeature::R4Trifecta => 1 << 2,
            GuardrailFeature::R5Format => 1 << 3,
            GuardrailFeature::R6SysPromptLeak => 1 << 4,
            GuardrailFeature::R7TopicCompetitor => 1 << 5,
        }
    }

    /// Grant a feature (builder).
    #[must_use]
    pub fn grant(mut self, feature: GuardrailFeature) -> Self {
        self.granted |= Self::bit(feature);
        self
    }

    /// Is this gated feature granted?
    #[must_use]
    pub fn allows(&self, feature: GuardrailFeature) -> bool {
        self.granted & Self::bit(feature) != 0
    }

    /// Is this rail enabled? A free-default rail (`feature == None`) is always
    /// enabled; a gated rail requires its feature to be granted (§2.7).
    #[must_use]
    pub fn enables(&self, feature: Option<GuardrailFeature>) -> bool {
        match feature {
            None => true,
            Some(f) => self.allows(f),
        }
    }

    /// Build a gate from a resolved entitlement set (§2.7): map each
    /// `f_guardrail_*` boolean (deny-overrides-grant, already resolved in
    /// Postgres) to its [`GuardrailFeature`] grant. The free defaults (R1, R3
    /// schema-val, R8) carry no flag and are unaffected.
    #[must_use]
    pub fn from_resolved(resolved: &crate::entitlement_cache::ResolvedEntitlements) -> Self {
        let mut gate = Self::free_defaults_only();
        if resolved.f_guardrail_r2 {
            gate = gate.grant(GuardrailFeature::R2SecretsPii);
        }
        if resolved.f_guardrail_r3_pinning {
            gate = gate.grant(GuardrailFeature::R3DefinitionPinning);
        }
        if resolved.f_guardrail_r4 {
            gate = gate.grant(GuardrailFeature::R4Trifecta);
        }
        if resolved.f_guardrail_r5 {
            gate = gate.grant(GuardrailFeature::R5Format);
        }
        if resolved.f_guardrail_r6 {
            gate = gate.grant(GuardrailFeature::R6SysPromptLeak);
        }
        if resolved.f_guardrail_r7 {
            gate = gate.grant(GuardrailFeature::R7TopicCompetitor);
        }
        gate
    }

    /// Resolve the gate for a tenant from the entitlement cache (§2.7). Warm
    /// reads never hit Postgres. A `None` cache (OSS self-host / dev with no
    /// Postgres) grants every gated rail — self-host gets full enforcement.
    pub async fn resolve(
        cache: Option<&crate::entitlement_cache::EntitlementCache>,
        tenant: uuid::Uuid,
    ) -> Self {
        match cache {
            Some(c) => {
                let resolved = c.resolved(tenant).await;
                Self::from_resolved(&resolved)
            }
            None => Self::all(),
        }
    }
}

/// The boxed-future return type for [`Rail::evaluate`].
pub type RailFuture<'a> = Pin<Box<dyn Future<Output = Result<RailOutcome, RailError>> + Send + 'a>>;

/// One guardrail. Pure over [`GuardrailContext`]; the dispatcher stamps
/// latency, maps errors to the fail-mode, and records the verdict.
pub trait Rail: Send + Sync {
    /// Stable rail id recorded in the ledger (e.g. `"R4_trifecta"`).
    fn name(&self) -> &'static str;

    /// Policy version recorded with each verdict (e.g. `"r4@1"`), bumped when
    /// the rail's logic/threshold changes (§2.5 `policy_version`).
    fn policy_version(&self) -> &'static str;

    /// Which side(s) this rail runs on.
    fn sides(&self) -> Sides;

    /// Fail-closed (security) or fail-open-loud (quality) (§0).
    fn fail_mode(&self) -> FailMode;

    /// The entitlement flag gating this rail, or `None` for a free default.
    fn feature(&self) -> Option<GuardrailFeature>;

    /// Evaluate the rail. MUST NOT perform network/disk I/O on the hot path.
    fn evaluate<'a>(&'a self, ctx: &'a GuardrailContext<'a>) -> RailFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_default_rail_always_enabled() {
        let gate = RailGate::free_defaults_only();
        assert!(gate.enables(None), "free-default rail runs with no grants");
        assert!(!gate.enables(Some(GuardrailFeature::R4Trifecta)));
    }

    #[test]
    fn granting_a_feature_enables_only_that_rail() {
        let gate = RailGate::free_defaults_only().grant(GuardrailFeature::R4Trifecta);
        assert!(gate.allows(GuardrailFeature::R4Trifecta));
        assert!(gate.enables(Some(GuardrailFeature::R4Trifecta)));
        // A different gated feature stays denied (deny-by-default).
        assert!(!gate.allows(GuardrailFeature::R2SecretsPii));
        assert!(!gate.enables(Some(GuardrailFeature::R2SecretsPii)));
    }

    #[test]
    fn all_grants_every_gated_feature() {
        let gate = RailGate::all();
        for f in GuardrailFeature::ALL {
            assert!(gate.allows(f), "RailGate::all must grant {f:?}");
        }
        assert!(gate.enables(None));
    }

    #[test]
    fn bits_are_distinct() {
        // No two features share a bit (a copy-paste in `bit()` would alias).
        let mut seen = 0u8;
        for f in GuardrailFeature::ALL {
            let b = RailGate::bit(f);
            assert_eq!(seen & b, 0, "feature {f:?} aliases another bit");
            seen |= b;
        }
    }

    /// §2.7: a resolved entitlement set maps `f_guardrail_*` → gate grants;
    /// toggling one flag enables exactly that rail (no rebuild).
    #[test]
    fn gate_from_resolved_maps_guardrail_flags() {
        use crate::entitlement_cache::ResolvedEntitlements;

        // deny_all → no gated rail granted; free defaults still run.
        let gate = RailGate::from_resolved(&ResolvedEntitlements::deny_all());
        assert!(!gate.allows(GuardrailFeature::R4Trifecta));
        assert!(gate.enables(None));

        // Flip only R4 + R2 on (a workspace_entitlements override).
        let mut resolved = ResolvedEntitlements::deny_all();
        resolved.f_guardrail_r4 = true;
        resolved.f_guardrail_r2 = true;
        let gate = RailGate::from_resolved(&resolved);
        assert!(gate.allows(GuardrailFeature::R4Trifecta));
        assert!(gate.allows(GuardrailFeature::R2SecretsPii));
        assert!(
            !gate.allows(GuardrailFeature::R7TopicCompetitor),
            "an ungranted rail stays denied"
        );
    }
}
