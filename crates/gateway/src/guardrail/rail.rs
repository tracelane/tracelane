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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    /// Postgres) resolves to the FREE tier: the five ungated rails still run
    /// (they never consult this gate), and the four paid rails require a
    /// control-plane grant. — this previously granted every gated rail.
    pub async fn resolve(
        cache: Option<&crate::entitlement_cache::EntitlementCache>,
        tenant: uuid::Uuid,
    ) -> Self {
        match cache {
            Some(c) => {
                let resolved = c.resolved(tenant).await;
                Self::from_resolved(&resolved)
            }
            // NO-CACHE -> the FREE tier., fixed 2026-08-04.
            //
            // This previously returned `Self::all()`, granting every gated rail
            // when no control plane exists — so an OSS self-host received the
            // Team-tier rails (R2 PII, R5 format, R6 sysprompt-leak, R7 topic)
            // and ran MORE guardrails than a paying Builder customer. That is
            // the exact inversion `.claude/rules/tenancy.md` forbids: a no-cache
            // path that GRANTS instead of denying produces no error, no alert
            // and no complaint, so nothing ever looked wrong.
            //
            // `free_defaults_only()` is now precisely the right answer and needs
            // no OSS-specific grant path: the five free rails (R1 cost,
            // R3 schema, R3 pinning, R4 trifecta, R8 injection) are UNGATED —
            // they return `None` from `Rail::feature()` and never consult this
            // gate at all — so an empty gate still runs every one of them. The
            // four paid rails (R2, R5, R6, R7) require a real control-plane
            // grant, here as everywhere else.
            //
            // Building a separate "OSS rail set" here would reintroduce the
            // second grant path this fix removes. Do not.
            None => Self::free_defaults_only(),
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

    // ──: the no-cache arm must resolve to the FREE tier ──────────────
    //
    // MECHANISM assertions. The bug these replace was invisible precisely
    // because outcomes looked fine: every rail ran, nothing errored, nobody was
    // billed wrongly. So assert the GATE STATE, not that requests succeed.

    /// The regression itself. Before this arm was `Self::all`.
    #[tokio::test]
    async fn no_cache_resolves_to_free_tier_never_all() {
        let gate = RailGate::resolve(None, uuid::Uuid::from_u128(1)).await;

        // Every PAID rail must be denied without a control plane.
        for paid in [
            GuardrailFeature::R2SecretsPii,
            GuardrailFeature::R5Format,
            GuardrailFeature::R6SysPromptLeak,
            GuardrailFeature::R7TopicCompetitor,
        ] {
            assert!(
                !gate.allows(paid),
                "no-cache granted paid rail {paid:?} — the no-cache inversion is back"
            );
            assert!(!gate.enables(Some(paid)));
        }

        // And it is exactly the free gate — not "all minus a few".
        assert_eq!(
            gate,
            RailGate::free_defaults_only(),
            "no-cache must be the free gate exactly"
        );
    }

    /// The five free rails do not consult the gate at all, so an empty gate
    /// still runs them. This is what makes a separate OSS grant path
    /// unnecessary — and it is the half that would break if someone "fixed"
    /// the inversion by gating the free five instead.
    #[test]
    fn free_five_run_under_an_empty_gate() {
        let gate = RailGate::free_defaults_only();
        assert!(
            gate.enables(None),
            "an ungated rail must run with zero grants"
        );
    }

    /// The founder ruling of 2026-08-04, pinned: agent-safety + basic
    /// correctness are FREE. If someone re-gates either rail, this fails.
    #[test]
    fn agent_safety_rails_are_ungated() {
        use crate::guardrail::rails::{r3_tool_safety::R3Pinning, r4_trifecta::R4Trifecta};
        assert!(
            Rail::feature(&R3Pinning::default()).is_none(),
            "R3 tool-definition pinning (MCP rug-pull) must stay FREE"
        );
        assert!(
            Rail::feature(&R4Trifecta::default()).is_none(),
            "R4 lethal-trifecta must stay FREE"
        );
    }

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
