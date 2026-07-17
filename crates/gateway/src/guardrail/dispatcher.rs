//! Concurrent rail dispatcher (the guardrail spec §2.6). Runs every
//! enabled rail for one side concurrently, applies a per-rail timeout + panic
//! seam, maps a [`RailError`] to the rail's fail-mode (security → block,
//! quality → fail-open-loud), captures per-rail latency, and aggregates the
//! per-rail outcomes into one [`Decision`] using `block > redact > warn > allow`.
//!
//! Concurrency uses `FuturesUnordered`, not `JoinSet`: rails borrow the
//! [`GuardrailContext`], so we poll them concurrently on the current task
//! rather than spawning `'static` tasks — this avoids an `Arc` clone of the
//! context on the hot path ("zero allocation past accept where avoidable",
//! CLAUDE.md) while still satisfying the spec's concurrent-dispatch + per-rail-
//!
//! No `RailError` is ever silently dropped (§5): every error/timeout/panic
//! produces a recorded outcome with a reason code.

use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

use futures::FutureExt;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::outcome::{Decision, FailMode, Outcome, RailError, RailOutcome, Side};
use crate::guardrail::rail::{Rail, RailGate};

/// Default per-rail timeout (§2.6). Deterministic rails finish in microseconds,
/// so a 2ms ceiling means a timeout here is a bug — handled per fail-mode.
pub const DEFAULT_PER_RAIL_TIMEOUT: Duration = Duration::from_millis(2);

/// One rail's recorded result for the verdict `rails[]` array (§2.5). The
/// dispatcher stamps `latency_micros`; `policy_version` comes from the rail.
#[derive(Debug, Clone)]
pub struct RailRecord {
    pub rail: &'static str,
    pub policy_version: &'static str,
    pub latency_micros: u64,
    pub outcome: RailOutcome,
}

/// The aggregate result for one side, recorded once per side (§2.5).
#[derive(Debug, Clone)]
pub struct SideOutcome {
    pub side: Side,
    pub decision: Decision,
    pub records: Vec<RailRecord>,
    pub total_latency_micros: u64,
}

impl SideOutcome {
    /// Rail ids that failed open — quality rails that errored but proceeded.
    /// Present in the verdict iff non-empty (§2.5 `fail_open_rails`).
    #[must_use]
    pub fn fail_open_rails(&self) -> Vec<&'static str> {
        self.records
            .iter()
            .filter(|r| r.outcome.outcome == Outcome::FailOpen)
            .map(|r| r.rail)
            .collect()
    }

    /// Did any rail block this side?
    #[must_use]
    pub fn is_block(&self) -> bool {
        self.decision.is_block()
    }
}

/// Owns the enabled rail set and runs them per side.
pub struct Dispatcher {
    rails: Vec<Box<dyn Rail>>,
    per_rail_timeout: Duration,
}

impl Dispatcher {
    #[must_use]
    pub fn new(rails: Vec<Box<dyn Rail>>) -> Self {
        Self {
            rails,
            per_rail_timeout: DEFAULT_PER_RAIL_TIMEOUT,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, per_rail_timeout: Duration) -> Self {
        self.per_rail_timeout = per_rail_timeout;
        self
    }

    #[must_use]
    pub fn rail_count(&self) -> usize {
        self.rails.len()
    }

    /// Evaluate all enabled rails for `side` and aggregate (§2.6).
    pub async fn evaluate_side(
        &self,
        side: Side,
        ctx: &GuardrailContext<'_>,
        gate: &RailGate,
    ) -> SideOutcome {
        let started = Instant::now();
        let timeout = self.per_rail_timeout;

        let mut futs = FuturesUnordered::new();
        for rail in &self.rails {
            if !rail.sides().includes(side) {
                continue;
            }
            if !gate.enables(rail.feature()) {
                continue;
            }
            let name = rail.name();
            let policy_version = rail.policy_version();
            let fail_mode = rail.fail_mode();
            futs.push(async move {
                let start = Instant::now();
                // Timeout wraps a catch_unwind seam (§5 DetectorPanic): a
                // panicking detector must never take the gateway down.
                let evaluated = tokio::time::timeout(
                    timeout,
                    AssertUnwindSafe(rail.evaluate(ctx)).catch_unwind(),
                )
                .await;
                let latency_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                let outcome = match evaluated {
                    Ok(Ok(Ok(o))) => o,
                    Ok(Ok(Err(e))) => Self::map_error(name, fail_mode, &e),
                    Ok(Err(_panic)) => Self::map_error(name, fail_mode, &RailError::DetectorPanic),
                    Err(_elapsed) => Self::map_error(name, fail_mode, &RailError::Timeout),
                };
                RailRecord {
                    rail: name,
                    policy_version,
                    latency_micros,
                    outcome,
                }
            });
        }

        let mut records: Vec<RailRecord> = Vec::with_capacity(futs.len());
        while let Some(record) = futs.next().await {
            records.push(record);
        }
        // FuturesUnordered completes out of order; sort by rail id so the
        // ledger record + hash are deterministic for a given rail set.
        records.sort_by_key(|r| r.rail);

        let decision = Decision::from_outcomes(records.iter().map(|r| &r.outcome.outcome));
        let total_latency_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        SideOutcome {
            side,
            decision,
            records,
            total_latency_micros,
        }
    }

    /// Map a [`RailError`] to an outcome per the rail's fail-mode (§0, §5):
    /// security → **block** (fail closed); quality → **fail_open** (proceed,
    /// recorded loud). The reason code is always preserved.
    fn map_error(rail: &'static str, fail_mode: FailMode, err: &RailError) -> RailOutcome {
        match fail_mode {
            FailMode::Closed => {
                tracing::warn!(rail, error = %err, "guardrail rail failed CLOSED — blocking");
                RailOutcome::block(err.reason_code())
            }
            FailMode::OpenLoud => {
                tracing::warn!(
                    rail,
                    error = %err,
                    "tracelane.guardrail.fail_open=true — quality rail failed OPEN (proceeds, recorded)"
                );
                RailOutcome::fail_open(err.reason_code())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::CapabilityRegistry;
    use crate::guardrail::context::SessionState;
    use crate::guardrail::outcome::{Sides, reason_codes};
    use crate::guardrail::rail::{GuardrailFeature, RailFuture};
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};
    use ulid::Ulid;
    use uuid::Uuid;

    fn minimal_request() -> ChatRequest {
        ChatRequest {
            model: "claude-sonnet-4-6".to_string(),
            system: None,
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hi".to_string()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
        }
    }

    /// Build a context + dispatch in one scope (the context borrows locals).
    async fn run(rails: Vec<Box<dyn Rail>>, side: Side, gate: RailGate) -> SideOutcome {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(7));
        let req = minimal_request();
        let reg = CapabilityRegistry::new();
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &req,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        Dispatcher::new(rails)
            .with_timeout(Duration::from_millis(50))
            .evaluate_side(side, &ctx, &gate)
            .await
    }

    // ── Mock rails ─────────────────────────────────────────────────────────
    macro_rules! mock_rail {
        ($ty:ident, $name:literal, $sides:expr, $fail:expr, $feat:expr, $body:expr) => {
            struct $ty;
            impl Rail for $ty {
                fn name(&self) -> &'static str {
                    $name
                }
                fn policy_version(&self) -> &'static str {
                    concat!($name, "@1")
                }
                fn sides(&self) -> Sides {
                    $sides
                }
                fn fail_mode(&self) -> FailMode {
                    $fail
                }
                fn feature(&self) -> Option<GuardrailFeature> {
                    $feat
                }
                fn evaluate<'a>(&'a self, _ctx: &'a GuardrailContext<'a>) -> RailFuture<'a> {
                    Box::pin(async move { $body })
                }
            }
        };
    }

    mock_rail!(
        AllowRail,
        "allow",
        Sides::Both,
        FailMode::OpenLoud,
        None,
        Ok(RailOutcome::allow())
    );
    mock_rail!(
        WarnRail,
        "warn",
        Sides::Both,
        FailMode::OpenLoud,
        None,
        Ok(RailOutcome::warn(reason_codes::COMPETITOR_MENTION))
    );
    mock_rail!(
        RedactRail,
        "redact",
        Sides::Both,
        FailMode::OpenLoud,
        None,
        Ok(RailOutcome::redact(reason_codes::SECRET_DETECTED))
    );
    mock_rail!(
        BlockRail,
        "block",
        Sides::Both,
        FailMode::Closed,
        None,
        Ok(RailOutcome::block(
            reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION
        ))
    );
    mock_rail!(
        SecErrRail,
        "sec_err",
        Sides::Both,
        FailMode::Closed,
        None,
        Err(RailError::DependencyUnavailable("pin-store"))
    );
    mock_rail!(
        QualErrRail,
        "qual_err",
        Sides::Both,
        FailMode::OpenLoud,
        None,
        Err(RailError::ConfigMissing("format-schema"))
    );
    mock_rail!(
        ResponseOnlyRail,
        "resp_only",
        Sides::ResponseOnly,
        FailMode::OpenLoud,
        None,
        Ok(RailOutcome::block(reason_codes::SYS_PROMPT_LEAK))
    );
    mock_rail!(
        GatedR4Rail,
        "gated_r4",
        Sides::Both,
        FailMode::Closed,
        Some(GuardrailFeature::R4Trifecta),
        Ok(RailOutcome::block(
            reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION
        ))
    );

    struct PanicRail(FailMode);
    impl Rail for PanicRail {
        fn name(&self) -> &'static str {
            "panic"
        }
        fn policy_version(&self) -> &'static str {
            "panic@1"
        }
        fn sides(&self) -> Sides {
            Sides::Both
        }
        fn fail_mode(&self) -> FailMode {
            self.0
        }
        fn feature(&self) -> Option<GuardrailFeature> {
            None
        }
        fn evaluate<'a>(&'a self, _ctx: &'a GuardrailContext<'a>) -> RailFuture<'a> {
            Box::pin(async move { panic!("simulated detector crash") })
        }
    }

    struct SlowRail;
    impl Rail for SlowRail {
        fn name(&self) -> &'static str {
            "slow"
        }
        fn policy_version(&self) -> &'static str {
            "slow@1"
        }
        fn sides(&self) -> Sides {
            Sides::Both
        }
        fn fail_mode(&self) -> FailMode {
            FailMode::Closed
        }
        fn feature(&self) -> Option<GuardrailFeature> {
            None
        }
        fn evaluate<'a>(&'a self, _ctx: &'a GuardrailContext<'a>) -> RailFuture<'a> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                Ok(RailOutcome::allow())
            })
        }
    }

    // ── Tests ──────────────────────────────────────────────────────────────

    /// P0.5 done-test: mixed outcomes → correct aggregate + per-rail latency.
    #[tokio::test]
    async fn mixed_outcomes_aggregate_to_most_severe_with_latency() {
        let out = run(
            vec![
                Box::new(AllowRail),
                Box::new(WarnRail),
                Box::new(RedactRail),
                Box::new(BlockRail),
            ],
            Side::Request,
            RailGate::all(),
        )
        .await;
        assert_eq!(out.decision, Decision::Block, "block wins precedence");
        assert_eq!(out.records.len(), 4);
        // every rail recorded a latency (micros), deterministic name order.
        assert_eq!(
            out.records.iter().map(|r| r.rail).collect::<Vec<_>>(),
            vec!["allow", "block", "redact", "warn"]
        );
        // total latency is captured.
        assert!(out.total_latency_micros < 1_000_000);
    }

    #[tokio::test]
    async fn redact_wins_over_warn_when_no_block() {
        let out = run(
            vec![
                Box::new(AllowRail),
                Box::new(WarnRail),
                Box::new(RedactRail),
            ],
            Side::Request,
            RailGate::all(),
        )
        .await;
        assert_eq!(out.decision, Decision::Redact);
    }

    #[tokio::test]
    async fn security_error_fails_closed_quality_error_fails_open() {
        let out = run(
            vec![Box::new(SecErrRail), Box::new(QualErrRail)],
            Side::Request,
            RailGate::all(),
        )
        .await;
        // Security rail error → block (fail closed) → aggregate blocks.
        assert_eq!(out.decision, Decision::Block);
        let sec = out.records.iter().find(|r| r.rail == "sec_err").unwrap();
        assert_eq!(sec.outcome.outcome, Outcome::Block);
        assert_eq!(
            sec.outcome.reason_code,
            Some(reason_codes::DEPENDENCY_UNAVAILABLE)
        );
        // Quality rail error → fail_open (recorded, proceeds).
        let qual = out.records.iter().find(|r| r.rail == "qual_err").unwrap();
        assert_eq!(qual.outcome.outcome, Outcome::FailOpen);
        assert_eq!(qual.outcome.reason_code, Some(reason_codes::CONFIG_MISSING));
        assert_eq!(out.fail_open_rails(), vec!["qual_err"]);
    }

    #[tokio::test]
    async fn panic_is_caught_and_mapped_to_fail_mode() {
        // Security panic → block.
        let out = run(
            vec![Box::new(PanicRail(FailMode::Closed))],
            Side::Request,
            RailGate::all(),
        )
        .await;
        assert_eq!(out.decision, Decision::Block);
        assert_eq!(
            out.records[0].outcome.reason_code,
            Some(reason_codes::DETECTOR_ERROR)
        );

        // Quality panic → fail_open (gateway must NOT go down).
        let out = run(
            vec![Box::new(PanicRail(FailMode::OpenLoud))],
            Side::Request,
            RailGate::all(),
        )
        .await;
        assert_eq!(out.decision, Decision::Allow);
        assert_eq!(out.records[0].outcome.outcome, Outcome::FailOpen);
    }

    #[tokio::test]
    async fn timeout_maps_to_fail_mode() {
        // SlowRail sleeps 500ms; dispatcher timeout is 50ms → security block.
        let out = run(vec![Box::new(SlowRail)], Side::Request, RailGate::all()).await;
        assert_eq!(out.decision, Decision::Block);
        assert_eq!(
            out.records[0].outcome.reason_code,
            Some(reason_codes::RAIL_TIMEOUT)
        );
    }

    #[tokio::test]
    async fn response_only_rail_skipped_on_request_side() {
        let out = run(
            vec![Box::new(ResponseOnlyRail)],
            Side::Request,
            RailGate::all(),
        )
        .await;
        assert!(
            out.records.is_empty(),
            "response-only rail must not run request-side"
        );
        assert_eq!(out.decision, Decision::Allow);

        // …but it runs response-side.
        let out = run(
            vec![Box::new(ResponseOnlyRail)],
            Side::Response,
            RailGate::all(),
        )
        .await;
        assert_eq!(out.records.len(), 1);
        assert_eq!(out.decision, Decision::Block);
    }

    /// P0.6 precondition: a gated rail is skipped without its entitlement and
    /// runs with it — no rebuild.
    #[tokio::test]
    async fn gated_rail_respects_entitlement() {
        // Not granted → skipped → allow.
        let out = run(
            vec![Box::new(GatedR4Rail)],
            Side::Request,
            RailGate::free_defaults_only(),
        )
        .await;
        assert!(out.records.is_empty());
        assert_eq!(out.decision, Decision::Allow);

        // Granted → runs → block.
        let out = run(
            vec![Box::new(GatedR4Rail)],
            Side::Request,
            RailGate::free_defaults_only().grant(GuardrailFeature::R4Trifecta),
        )
        .await;
        assert_eq!(out.records.len(), 1);
        assert_eq!(out.decision, Decision::Block);
    }

    #[tokio::test]
    async fn empty_rail_set_allows() {
        let out = run(Vec::new(), Side::Request, RailGate::all()).await;
        assert_eq!(out.decision, Decision::Allow);
        assert!(out.records.is_empty());
    }
}
