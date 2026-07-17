//! R1 — Cost / token / loop caps (the guardrail spec §3 R1). Denial-of-
//! wallet, runaway loops, per-tenant overspend (OWASP LLM10). Free-tier default
//! (ungated) — every workspace gets safe caps with no config.
//!
//! Request-side checks (over `est_input_tokens` + `session`): input-token cap →
//! block `INPUT_TOKEN_CAP`; loop cap (calls in the rolling window) → block
//! `LOOP_CAP`; budget cap (`spend_in_window + est_cost > budget`) → block
//! `BUDGET_CAP`, or warn within `warn_threshold_pct` of budget. Unknown spend
//! (session cache miss) under a HARD budget → block `BUDGET_STATE_UNKNOWN` (fail
//! closed); under a soft budget → allow (cannot evaluate).
//!
//! Response-side check (over `usage`): output-token cap → block
//! `OUTPUT_TOKEN_CAP`. On the streaming path this terminates generation
//! mid-stream once the SSE call-site wiring lands (with R5/R6); the rail logic
//! is identical, fed the running output count.
//!
//! Cost is a pre-flight ESTIMATE (a flat per-1k-input-token cents rate) — the
//! precise billed cost is the meter's job; R1 is a guardrail, not billing.
//! `details` carry token counts + cents only (no secrets/PII, §2.5).

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::outcome::{FailMode, RailError, RailOutcome, Sides, reason_codes};
use crate::guardrail::rail::{GuardrailFeature, Rail, RailFuture};

/// R1 caps configuration. `None` disables an individual cap. Per-workspace
/// (loaded from settings/entitlements in the future); V1 ships safe defaults.
#[derive(Debug, Clone, Copy)]
pub struct R1Config {
    pub max_input_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub budget_cents: Option<u64>,
    pub max_calls_per_window: Option<u32>,
    /// Flat pre-flight cost estimate, cents per 1k input tokens.
    pub cost_per_1k_input_tokens_cents: f64,
    /// Warn band: warn when a usage projection reaches this percent of a cap.
    pub warn_threshold_pct: u8,
    /// If true, an unknown spend (session cache miss) under a configured budget
    /// fails CLOSED (`BUDGET_STATE_UNKNOWN`) rather than allowing.
    pub hard_budget: bool,
}

impl Default for R1Config {
    fn default() -> Self {
        Self {
            max_input_tokens: Some(200_000),
            max_output_tokens: Some(32_000),
            // No budget cap by default — opt-in per workspace. Loop + token caps
            // are the always-on free-tier protection.
            budget_cents: None,
            max_calls_per_window: Some(100),
            cost_per_1k_input_tokens_cents: 1.0,
            warn_threshold_pct: 80,
            hard_budget: false,
        }
    }
}

/// R1 cost/token/loop rail.
#[derive(Debug, Clone, Default)]
pub struct R1Cost {
    config: R1Config,
}

impl R1Cost {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_config(config: R1Config) -> Self {
        Self { config }
    }

    /// Flat pre-flight cost estimate in cents (ceil), from input tokens.
    fn est_cost_cents(&self, est_input_tokens: u32) -> u64 {
        let cents =
            (f64::from(est_input_tokens) / 1000.0) * self.config.cost_per_1k_input_tokens_cents;
        cents.ceil().max(0.0) as u64
    }

    /// Pure evaluation core (sync, testable).
    pub fn evaluate_sync(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        // ── Response-side: only the output-token cap applies ───────────────
        // Detect the response side by the presence of the response buffer
        // (`usage` may be absent mid-stream before the first usage update).
        if ctx.response_buf.is_some() {
            if let (Some(usage), Some(max)) = (ctx.usage, self.config.max_output_tokens) {
                if usage.output_tokens > max {
                    return RailOutcome::block(reason_codes::OUTPUT_TOKEN_CAP).with_details(
                        serde_json::json!({ "output_tokens": usage.output_tokens, "max": max }),
                    );
                }
            }
            return RailOutcome::not_applicable();
        }

        // ── Request-side: input cap ────────────────────────────────────────
        if let Some(max) = self.config.max_input_tokens {
            if ctx.est_input_tokens > max {
                return RailOutcome::block(reason_codes::INPUT_TOKEN_CAP).with_details(
                    serde_json::json!({ "est_input_tokens": ctx.est_input_tokens, "max": max }),
                );
            }
        }

        // ── Loop cap (calls in the rolling window) ─────────────────────────
        if let Some(max) = self.config.max_calls_per_window {
            if ctx.session.calls_in_window >= max {
                return RailOutcome::block(reason_codes::LOOP_CAP).with_details(
                    serde_json::json!({
                        "calls_in_window": ctx.session.calls_in_window,
                        "max": max,
                    }),
                );
            }
        }

        // ── Budget cap ─────────────────────────────────────────────────────
        if let Some(budget) = self.config.budget_cents {
            let est = self.est_cost_cents(ctx.est_input_tokens);
            match ctx.session.spend_cents_in_window {
                Some(spent) => {
                    let projected = spent.saturating_add(est);
                    if projected > budget {
                        return RailOutcome::block(reason_codes::BUDGET_CAP).with_details(
                            serde_json::json!({
                                "spend_cents": spent,
                                "est_cost_cents": est,
                                "budget_cents": budget,
                            }),
                        );
                    }
                    // Warn band: projected within warn_threshold_pct of budget.
                    if projected.saturating_mul(100)
                        >= budget.saturating_mul(u64::from(self.config.warn_threshold_pct))
                    {
                        return RailOutcome::warn(reason_codes::BUDGET_CAP).with_details(
                            serde_json::json!({
                                "spend_cents": spent,
                                "est_cost_cents": est,
                                "budget_cents": budget,
                                "warn_threshold_pct": self.config.warn_threshold_pct,
                            }),
                        );
                    }
                }
                None => {
                    // Unknown spend (session cache miss). Hard budget → fail
                    // closed; soft budget → cannot evaluate, allow.
                    if self.config.hard_budget {
                        return RailOutcome::block(reason_codes::BUDGET_STATE_UNKNOWN)
                            .with_details(
                                serde_json::json!({ "budget_cents": budget, "spend": "unknown" }),
                            );
                    }
                }
            }
        }

        RailOutcome::allow()
    }
}

impl Rail for R1Cost {
    fn name(&self) -> &'static str {
        "R1_cost"
    }

    fn policy_version(&self) -> &'static str {
        "r1@1"
    }

    fn sides(&self) -> Sides {
        // Request-side: input/loop/budget. Response-side: output-token cap
        // (enforced mid-stream once the SSE wiring lands with R5/R6).
        Sides::Both
    }

    fn fail_mode(&self) -> FailMode {
        // R1 is a quality/cost rail, not in the security set — a crash in the
        // cost check must not deny the user (fail open, loud). The
        // unknown-budget fail-CLOSED is the rail's RETURN value
        // (`BUDGET_STATE_UNKNOWN`), not error handling.
        FailMode::OpenLoud
    }

    fn feature(&self) -> Option<GuardrailFeature> {
        // Free-tier default — always on, no entitlement.
        None
    }

    fn evaluate<'a>(&'a self, ctx: &'a GuardrailContext<'a>) -> RailFuture<'a> {
        Box::pin(async move { Ok::<_, RailError>(self.evaluate_sync(ctx)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::CapabilityRegistry;
    use crate::guardrail::context::{ResponseBuffer, SessionState};
    use crate::guardrail::outcome::Outcome;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId, Usage};
    use ulid::Ulid;
    use uuid::Uuid;

    fn req() -> ChatRequest {
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

    /// Build a request-side context with a given session + overridden token est.
    fn request_ctx<'r>(
        tenant: &'r TenantId,
        request: &'r ChatRequest,
        reg: &'r CapabilityRegistry,
        session: SessionState,
        est_input_tokens: u32,
    ) -> GuardrailContext<'r> {
        let mut ctx = GuardrailContext::from_request(
            tenant,
            None,
            Ulid::from_parts(1, 1),
            request,
            reg,
            Vec::new(),
            session,
        );
        ctx.est_input_tokens = est_input_tokens;
        ctx
    }

    /// §3 R1 test: budget 100c, spend 99c, est 5c → block BUDGET_CAP.
    #[test]
    fn budget_cap_blocks() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(1));
        let r = req();
        let reg = CapabilityRegistry::new();
        let mut session = SessionState::fresh(None);
        session.spend_cents_in_window = Some(99);
        // 5000 input tokens @ 1c/1k = 5c est.
        let ctx = request_ctx(&tenant, &r, &reg, session, 5000);
        let rail = R1Cost::with_config(R1Config {
            budget_cents: Some(100),
            ..R1Config::default()
        });
        let out = rail.evaluate_sync(&ctx);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::BUDGET_CAP));
        assert_eq!(out.details["est_cost_cents"], 5);
    }

    /// §3 R1 test: max_calls 10, calls 10 → block LOOP_CAP.
    #[test]
    fn loop_cap_blocks() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(2));
        let r = req();
        let reg = CapabilityRegistry::new();
        let mut session = SessionState::fresh(None);
        session.calls_in_window = 10;
        let ctx = request_ctx(&tenant, &r, &reg, session, 10);
        let rail = R1Cost::with_config(R1Config {
            max_calls_per_window: Some(10),
            ..R1Config::default()
        });
        let out = rail.evaluate_sync(&ctx);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::LOOP_CAP));
    }

    /// §3 R1 test: streaming output exceeds cap → block OUTPUT_TOKEN_CAP.
    #[test]
    fn output_token_cap_blocks() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(3));
        let r = req();
        let reg = CapabilityRegistry::new();
        let buf = ResponseBuffer::new();
        let usage = Usage {
            input_tokens: 10,
            output_tokens: 150,
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        };
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &r,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        )
        .with_response(&buf, Some(&usage));
        let rail = R1Cost::with_config(R1Config {
            max_output_tokens: Some(100),
            ..R1Config::default()
        });
        let out = rail.evaluate_sync(&ctx);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::OUTPUT_TOKEN_CAP));
        assert_eq!(out.details["output_tokens"], 150);
    }

    /// §3 R1 test: unknown spend (cache miss) + hard budget → fail CLOSED with
    /// BUDGET_STATE_UNKNOWN (this is fail-closed, the rail's return value).
    #[test]
    fn unknown_spend_hard_budget_fails_closed() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(4));
        let r = req();
        let reg = CapabilityRegistry::new();
        let session = SessionState::fresh(None); // spend = None (cache cold)
        assert!(session.spend_cents_in_window.is_none());
        let ctx = request_ctx(&tenant, &r, &reg, session, 10);
        let rail = R1Cost::with_config(R1Config {
            budget_cents: Some(100),
            hard_budget: true,
            ..R1Config::default()
        });
        let out = rail.evaluate_sync(&ctx);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::BUDGET_STATE_UNKNOWN));
    }

    /// Unknown spend + SOFT budget → cannot evaluate → allow (not fail-closed).
    #[test]
    fn unknown_spend_soft_budget_allows() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(5));
        let r = req();
        let reg = CapabilityRegistry::new();
        let ctx = request_ctx(&tenant, &r, &reg, SessionState::fresh(None), 10);
        let rail = R1Cost::with_config(R1Config {
            budget_cents: Some(100),
            hard_budget: false,
            ..R1Config::default()
        });
        assert_eq!(rail.evaluate_sync(&ctx).outcome, Outcome::Allow);
    }

    /// Input-token cap → block INPUT_TOKEN_CAP.
    #[test]
    fn input_token_cap_blocks() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(6));
        let r = req();
        let reg = CapabilityRegistry::new();
        let ctx = request_ctx(&tenant, &r, &reg, SessionState::fresh(None), 500_000);
        let out = R1Cost::new().evaluate_sync(&ctx); // default max 200k
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::INPUT_TOKEN_CAP));
    }

    /// Budget warn band: projected within 80% of budget → warn.
    #[test]
    fn budget_warn_band() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(7));
        let r = req();
        let reg = CapabilityRegistry::new();
        let mut session = SessionState::fresh(None);
        session.spend_cents_in_window = Some(75);
        // 5c est → projected 80 == 80% of 100.
        let ctx = request_ctx(&tenant, &r, &reg, session, 5000);
        let rail = R1Cost::with_config(R1Config {
            budget_cents: Some(100),
            ..R1Config::default()
        });
        let out = rail.evaluate_sync(&ctx);
        assert_eq!(out.outcome, Outcome::Warn);
        assert_eq!(out.reason_code, Some(reason_codes::BUDGET_CAP));
    }

    /// A within-caps request → allow.
    #[test]
    fn within_caps_allows() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(8));
        let r = req();
        let reg = CapabilityRegistry::new();
        let ctx = request_ctx(&tenant, &r, &reg, SessionState::fresh(None), 100);
        assert_eq!(R1Cost::new().evaluate_sync(&ctx).outcome, Outcome::Allow);
    }
}
