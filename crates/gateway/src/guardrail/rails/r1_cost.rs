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
//! ## Multi-agent runaway caps (GWY-23)
//!
//! Three further request-side caps close the multi-agent cost-runaway surface.
//! All three are derived from the **transcript the request already carries** —
//! not from session-cache state — which matters: the hot path constructs
//! [`SessionState::fresh`] per request (`server.rs:1363`), so `calls_in_window`
//! and `spend_cents_in_window` are 0/unknown in production and the window-based
//! caps above are inert until a session cache is wired. The transcript-derived
//! caps fire on live `/v1/chat/completions` traffic today.
//!
//!   - **Step cap** (`STEP_CAP`) — one *step* is an assistant turn that proposed
//!     at least one tool call. An agent loop that has taken more steps than
//!     `max_steps_per_run` is not converging.
//!   - **Loop-hash** (`LOOP_HASH_REPEAT`) — every proposed tool call is
//!     fingerprinted as `blake3(name ‖ JCS(arguments))`. The same fingerprint
//!     repeating more than `max_identical_tool_calls` times in one run is the
//!     stuck-loop signature: the agent is re-issuing a byte-identical call and
//!     paying for it every time. Key order in the arguments cannot change the
//!     fingerprint (RFC 8785 canonicalization, the same one `def_hash` uses).
//!   - **Sub-agent depth** (`SUBAGENT_DEPTH_CAP`) — depth is the number of
//!     delegation tool calls that are still **open**: spawned in the transcript
//!     with no matching tool result yet. Each open delegation is one parent
//!     waiting on a child, so the count is the live nesting depth. A delegation
//!     that has returned is closed and costs no depth — which is what separates
//!     this from "count how many times a spawn tool appears".
//!
//! Fingerprints and counts only ever reach `details` as hashes/integers — never
//! argument values (§2.5).
//!
//! Response-side check (over `usage`): output-token cap → block
//! `OUTPUT_TOKEN_CAP`. On the streaming path this terminates generation
//! mid-stream once the SSE call-site wiring lands (with R5/R6); the rail logic
//! is identical, fed the running output count.
//!
//! Cost is a pre-flight ESTIMATE (a flat per-1k-input-token cents rate) — the
//! precise billed cost is the meter's job; R1 is a guardrail, not billing.
//! `details` carry token counts + cents only (no secrets/PII, §2.5).

use std::collections::{HashMap, HashSet};

use tracelane_shared::{ContentPart, Message, MessageContent, Role};

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::outcome::{FailMode, RailError, RailOutcome, Sides, reason_codes};
use crate::guardrail::rail::{GuardrailFeature, Rail, RailFuture};

/// Tool names that denote spawning a **sub-agent** (lowercased, exact match),
/// plus the `*subagent*` / `*sub_agent*` substring forms handled in
/// [`is_delegation_tool`]. Deliberately a short, high-precision list: the depth
/// cap is a block, so a tool that merely *sounds* agentic must not count.
pub const DEFAULT_DELEGATION_TOOLS: &[&str] = &[
    "task",
    "agent",
    "spawn_agent",
    "spawnagent",
    "run_agent",
    "run_subagent",
    "start_agent",
    "invoke_agent",
    "dispatch_agent",
    "delegate",
    "delegate_task",
    "create_subagent",
];

/// R1 caps configuration. `None` disables an individual cap. Per-workspace
/// (loaded from settings/entitlements in the future); V1 ships safe defaults.
#[derive(Debug, Clone, Copy)]
pub struct R1Config {
    pub max_input_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub budget_cents: Option<u64>,
    pub max_calls_per_window: Option<u32>,
    /// GWY-23 step cap: max agent steps (assistant turns proposing ≥1 tool
    /// call) in one run. `None` disables.
    pub max_steps_per_run: Option<u32>,
    /// GWY-23 loop-hash: max repeats of one identical `(name, arguments)` tool
    /// call within a run. `None` disables.
    pub max_identical_tool_calls: Option<u32>,
    /// GWY-23 sub-agent depth: max delegations open (spawned, not yet returned)
    /// at once. `None` disables.
    pub max_subagent_depth: Option<u32>,
    /// Tool names counted as a sub-agent delegation.
    pub delegation_tools: &'static [&'static str],
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
            // Runaway thresholds, not style guides. A legitimate deep agent run
            // lands well under each: the caps exist to stop an unbounded loop
            // billing a customer, so the default sits where "still working" and
            // "never going to converge" stop overlapping. Per ADR-055 a
            // false-positive block is worse than the failure it prevents, so the
            // defaults are deliberately generous and tunable DOWN per workspace.
            max_steps_per_run: Some(200),
            max_identical_tool_calls: Some(25),
            max_subagent_depth: Some(4),
            delegation_tools: DEFAULT_DELEGATION_TOOLS,
            cost_per_1k_input_tokens_cents: 1.0,
            warn_threshold_pct: 80,
            hard_budget: false,
        }
    }
}

/// Does this message represent one agent **step** — an assistant turn that
/// proposed at least one tool call? Covers both wire shapes (OpenAI
/// `message.tool_calls`, Anthropic `ContentPart::ToolUse`).
fn is_agent_step(m: &Message) -> bool {
    if m.role != Role::Assistant {
        return false;
    }
    if m.tool_calls.as_ref().is_some_and(|tc| !tc.is_empty()) {
        return true;
    }
    matches!(&m.content, MessageContent::Parts(parts)
        if parts.iter().any(|p| matches!(p, ContentPart::ToolUse { .. })))
}

/// Steps taken so far in this run — assistant turns that proposed a tool call.
///
/// A plain chat exchange has zero steps; each tool-calling turn of an agent loop
/// adds one, regardless of how many tools that turn called in parallel (a
/// fan-out is one step, which is what "step" means to the model doing it).
#[must_use]
pub fn steps_taken(messages: &[Message]) -> u32 {
    u32::try_from(messages.iter().filter(|m| is_agent_step(m)).count()).unwrap_or(u32::MAX)
}

/// Fingerprint one proposed tool call: `blake3(lp(name) ‖ lp(JCS(arguments)))`.
///
/// Uses the same RFC 8785 canonicalizer as `capability::def_hash`, so argument
/// key order / whitespace cannot split one repeated call into distinct
/// fingerprints — without that, a client re-serializing its arguments would
/// silently defeat the loop detector.
#[must_use]
pub fn call_fingerprint(name: &str, arguments: &serde_json::Value) -> blake3::Hash {
    let canonical = crate::audit_format::canonical_payload(arguments);
    let mut hasher = blake3::Hasher::new();
    for field in [name.as_bytes(), canonical.as_bytes()] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize()
}

/// Is `name` a sub-agent delegation tool?
#[must_use]
pub fn is_delegation_tool(name: &str, delegation_tools: &[&str]) -> bool {
    let lower = name.to_ascii_lowercase();
    delegation_tools.iter().any(|t| lower == *t)
        || lower.contains("subagent")
        || lower.contains("sub_agent")
}

/// How many sub-agent delegations are **open** — spawned in this transcript with
/// no matching tool result yet. A returned delegation is closed and costs no
/// depth, so this is the live nesting depth rather than a lifetime count.
#[must_use]
pub fn open_delegation_depth(ctx: &GuardrailContext<'_>, delegation_tools: &[&str]) -> u32 {
    let returned: HashSet<&str> = ctx
        .tool_results
        .iter()
        .filter_map(|r| r.tool_call_id)
        .collect();
    let open = ctx
        .tool_calls
        .iter()
        .filter(|c| is_delegation_tool(c.name, delegation_tools) && !returned.contains(c.id))
        .count();
    u32::try_from(open).unwrap_or(u32::MAX)
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

        // ── Step cap (GWY-23) ──────────────────────────────────────────────
        // Derived from the transcript, so it fires on live traffic even though
        // the hot path passes a fresh (empty) session — see the module docs.
        if let Some(max) = self.config.max_steps_per_run {
            let steps = steps_taken(ctx.messages);
            if steps >= max {
                return RailOutcome::block(reason_codes::STEP_CAP)
                    .with_details(serde_json::json!({ "steps": steps, "max": max }));
            }
        }

        // ── Loop-hash: the same call repeating (GWY-23) ────────────────────
        if let Some(max) = self.config.max_identical_tool_calls {
            let mut counts: HashMap<blake3::Hash, (u32, &str)> = HashMap::new();
            for call in &ctx.tool_calls {
                let fp = call_fingerprint(call.name, call.input);
                let entry = counts.entry(fp).or_insert((0, call.name));
                entry.0 += 1;
                if entry.0 >= max {
                    // Fingerprint hex + tool name only — never the arguments
                    // that were repeated (§2.5).
                    return RailOutcome::block(reason_codes::LOOP_HASH_REPEAT).with_details(
                        serde_json::json!({
                            "tool": call.name,
                            "repeats": entry.0,
                            "max": max,
                            "call_fingerprint": fp.to_hex().to_string(),
                        }),
                    );
                }
            }
        }

        // ── Sub-agent depth (GWY-23) ───────────────────────────────────────
        if let Some(max) = self.config.max_subagent_depth {
            let depth = open_delegation_depth(ctx, self.config.delegation_tools);
            if depth > max {
                return RailOutcome::block(reason_codes::SUBAGENT_DEPTH_CAP)
                    .with_details(serde_json::json!({ "open_delegations": depth, "max": max }));
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

    // ── GWY-23: step cap · loop-hash · sub-agent depth ─────────────────────
    //
    // Every cap gets its matching MUST-ACCEPT boundary case, one step below the
    // threshold. A cap that only ever blocks is indistinguishable from a rail
    // that blocks everything.

    use serde_json::json;
    use tracelane_shared::{ContentPart, ToolCall};

    /// An assistant turn that proposes one tool call (Anthropic shape).
    fn step(id: &str, name: &str, input: serde_json::Value) -> Message {
        Message {
            role: Role::Assistant,
            content: MessageContent::Parts(vec![ContentPart::ToolUse {
                id: id.to_string(),
                name: name.to_string(),
                input,
            }]),
            tool_call_id: None,
            tool_calls: None,
        }
    }

    /// The tool result that closes `id`.
    fn result_for(id: &str) -> Message {
        Message {
            role: Role::Tool,
            content: MessageContent::Text("done".to_string()),
            tool_call_id: Some(id.to_string()),
            tool_calls: None,
        }
    }

    fn req_with(messages: Vec<Message>) -> ChatRequest {
        ChatRequest {
            model: "claude-sonnet-4-6".to_string(),
            system: None,
            messages,
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
        }
    }

    /// `n` DISTINCT steps (arguments vary), so only the step cap can fire.
    fn distinct_steps(n: u32) -> Vec<Message> {
        (0..n)
            .map(|i| step(&format!("c{i}"), "search", json!({ "q": i })))
            .collect()
    }

    fn outcome_of(messages: Vec<Message>, config: R1Config) -> RailOutcome {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(0x6023));
        let r = req_with(messages);
        let reg = CapabilityRegistry::new();
        let ctx = request_ctx(&tenant, &r, &reg, SessionState::fresh(None), 10);
        R1Cost::with_config(config).evaluate_sync(&ctx)
    }

    /// A step is an ASSISTANT turn that proposed a tool call — in either wire
    /// shape. User turns, plain assistant prose and tool results are not steps.
    #[test]
    fn steps_counted_from_both_shapes_and_nothing_else() {
        let messages = vec![
            Message {
                role: Role::User,
                content: MessageContent::Text("go".to_string()),
                tool_call_id: None,
                tool_calls: None,
            },
            step("c1", "search", json!({})), // Anthropic ToolUse → step
            result_for("c1"),                // tool result → NOT a step
            Message {
                role: Role::Assistant, // OpenAI tool_calls → step
                content: MessageContent::Text("thinking".to_string()),
                tool_call_id: None,
                tool_calls: Some(vec![ToolCall {
                    id: "c2".to_string(),
                    name: "search".to_string(),
                    input: json!({}),
                }]),
            },
            Message {
                role: Role::Assistant, // prose only → NOT a step
                content: MessageContent::Text("here is the answer".to_string()),
                tool_call_id: None,
                tool_calls: None,
            },
        ];
        assert_eq!(steps_taken(&messages), 2);
        assert_eq!(steps_taken(&[]), 0, "a plain chat has taken no steps");
    }

    /// MUST REJECT: an agent run at the step cap → block STEP_CAP.
    #[test]
    fn step_cap_blocks_a_runaway_agent_loop() {
        let cfg = R1Config {
            max_steps_per_run: Some(12),
            ..R1Config::default()
        };
        let out = outcome_of(distinct_steps(12), cfg);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::STEP_CAP));
        assert_eq!(out.details["steps"], 12);
        assert_eq!(out.details["max"], 12);
    }

    /// MUST ACCEPT: one step below the cap → allow. Proves the block is the
    /// cap firing, not the rail rejecting tool-using transcripts wholesale.
    #[test]
    fn step_cap_allows_one_below_the_cap() {
        let cfg = R1Config {
            max_steps_per_run: Some(12),
            ..R1Config::default()
        };
        assert_eq!(outcome_of(distinct_steps(11), cfg).outcome, Outcome::Allow);
    }

    /// `None` disables the cap entirely — 500 steps pass.
    #[test]
    fn step_cap_none_disables() {
        let cfg = R1Config {
            max_steps_per_run: None,
            max_identical_tool_calls: None,
            ..R1Config::default()
        };
        assert_eq!(outcome_of(distinct_steps(500), cfg).outcome, Outcome::Allow);
    }

    /// The fingerprint is over the CANONICALIZED arguments, so a client that
    /// re-serializes with different key order cannot split one repeated call
    /// into two distinct fingerprints and slip past the loop detector.
    #[test]
    fn call_fingerprint_is_key_order_independent_and_name_bound() {
        let a = call_fingerprint("search", &json!({ "a": 1, "b": 2 }));
        let b = call_fingerprint("search", &json!({ "b": 2, "a": 1 }));
        assert_eq!(a, b, "key order must not change the fingerprint");

        let different_args = call_fingerprint("search", &json!({ "a": 1, "b": 3 }));
        assert_ne!(a, different_args, "different arguments → different call");

        let different_tool = call_fingerprint("fetch", &json!({ "a": 1, "b": 2 }));
        assert_ne!(a, different_tool, "the tool name is part of the identity");
    }

    /// MUST REJECT: the same call, byte-identical, repeated to the cap → block
    /// LOOP_HASH_REPEAT. This is the stuck-loop signature the step cap alone
    /// would not catch until 200 steps of billed spend.
    #[test]
    fn loop_hash_blocks_an_identical_repeated_call() {
        let cfg = R1Config {
            max_identical_tool_calls: Some(5),
            ..R1Config::default()
        };
        // Same tool, same arguments, different call ids (as a real loop emits).
        let messages: Vec<Message> = (0..5)
            .map(|i| step(&format!("c{i}"), "get_status", json!({ "job": "j-1" })))
            .collect();
        let out = outcome_of(messages, cfg);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::LOOP_HASH_REPEAT));
        assert_eq!(out.details["repeats"], 5);
        assert_eq!(out.details["tool"], "get_status");
        assert_eq!(
            out.details["call_fingerprint"],
            call_fingerprint("get_status", &json!({ "job": "j-1" }))
                .to_hex()
                .to_string()
        );
    }

    /// MUST ACCEPT: the same TOOL called many times with DIFFERENT arguments is
    /// productive work, not a loop — it must not block. This is the
    /// discriminating case: a detector that keyed on the tool name alone would
    /// fail here, and would break every real agent.
    #[test]
    fn loop_hash_allows_same_tool_with_different_arguments() {
        let cfg = R1Config {
            max_identical_tool_calls: Some(5),
            max_steps_per_run: None, // isolate the loop-hash check
            ..R1Config::default()
        };
        let messages: Vec<Message> = (0..40)
            .map(|i| step(&format!("c{i}"), "get_status", json!({ "job": i })))
            .collect();
        assert_eq!(outcome_of(messages, cfg).outcome, Outcome::Allow);
    }

    /// MUST ACCEPT: one repeat below the cap → allow.
    #[test]
    fn loop_hash_allows_one_below_the_cap() {
        let cfg = R1Config {
            max_identical_tool_calls: Some(5),
            ..R1Config::default()
        };
        let messages: Vec<Message> = (0..4)
            .map(|i| step(&format!("c{i}"), "get_status", json!({ "job": "j-1" })))
            .collect();
        assert_eq!(outcome_of(messages, cfg).outcome, Outcome::Allow);
    }

    /// Depth counts only OPEN delegations. Five spawns that have all returned
    /// are five finished sub-agents, not a five-deep stack — they must not
    /// block, or every completed multi-agent run would 403 on its next turn.
    #[test]
    fn subagent_depth_ignores_delegations_that_already_returned() {
        let cfg = R1Config {
            max_subagent_depth: Some(2),
            max_steps_per_run: None,
            max_identical_tool_calls: None,
            ..R1Config::default()
        };
        let mut messages = Vec::new();
        for i in 0..5 {
            let id = format!("d{i}");
            messages.push(step(&id, "spawn_agent", json!({ "goal": i })));
            messages.push(result_for(&id)); // closed
        }
        assert_eq!(outcome_of(messages, cfg).outcome, Outcome::Allow);
    }

    /// MUST REJECT: more open delegations than the cap → block
    /// SUBAGENT_DEPTH_CAP (the fork-bomb shape).
    #[test]
    fn subagent_depth_blocks_when_open_delegations_exceed_the_cap() {
        let cfg = R1Config {
            max_subagent_depth: Some(2),
            max_steps_per_run: None,
            max_identical_tool_calls: None,
            ..R1Config::default()
        };
        // Three spawns open at once (one returned, so it does not count).
        let messages = vec![
            step("d0", "spawn_agent", json!({ "goal": 0 })),
            result_for("d0"),
            step("d1", "spawn_agent", json!({ "goal": 1 })),
            step("d2", "Task", json!({ "goal": 2 })), // case-insensitive
            step("d3", "run_subagent", json!({ "goal": 3 })),
        ];
        let out = outcome_of(messages, cfg);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::SUBAGENT_DEPTH_CAP));
        assert_eq!(out.details["open_delegations"], 3);
        assert_eq!(out.details["max"], 2);
    }

    /// MUST ACCEPT: exactly at the cap is still allowed (the cap is the deepest
    /// permitted nesting, not the first forbidden one), and non-delegation
    /// tools never contribute depth however many are open.
    #[test]
    fn subagent_depth_allows_at_the_cap_and_ignores_ordinary_tools() {
        let cfg = R1Config {
            max_subagent_depth: Some(2),
            max_steps_per_run: None,
            max_identical_tool_calls: None,
            ..R1Config::default()
        };
        let at_cap = vec![
            step("d1", "spawn_agent", json!({ "goal": 1 })),
            step("d2", "delegate", json!({ "goal": 2 })),
        ];
        assert_eq!(outcome_of(at_cap, cfg).outcome, Outcome::Allow);

        let ordinary: Vec<Message> = (0..20)
            .map(|i| step(&format!("c{i}"), "search", json!({ "q": i })))
            .collect();
        assert_eq!(outcome_of(ordinary, cfg).outcome, Outcome::Allow);
    }

    /// The delegation matcher: exact names + the `subagent` / `sub_agent`
    /// substring forms, case-insensitively — and nothing that merely reads as
    /// agentic. `agent_logs` is the false positive a naive `contains("agent")`
    /// would produce, and it would block a perfectly ordinary tool.
    #[test]
    fn delegation_matcher_is_precise() {
        for yes in [
            "Task",
            "spawn_agent",
            "SPAWN_AGENT",
            "run_subagent",
            "my_sub_agent_runner",
            "createSubagent",
            "delegate",
        ] {
            assert!(
                is_delegation_tool(yes, DEFAULT_DELEGATION_TOOLS),
                "{yes} must count as a delegation"
            );
        }
        for no in [
            "agent_logs",
            "list_agents",
            "search",
            "get_agent_status",
            "taskboard_create",
        ] {
            assert!(
                !is_delegation_tool(no, DEFAULT_DELEGATION_TOOLS),
                "{no} must NOT count as a delegation"
            );
        }
    }

    /// The shipped defaults must not block an ordinary, healthy agent run —
    /// 30 varied steps with two sub-agents that returned. If this ever fails,
    /// the defaults have become a false-positive machine.
    #[test]
    fn production_defaults_allow_a_healthy_agent_run() {
        let mut messages = distinct_steps(30);
        for i in 0..2 {
            let id = format!("d{i}");
            messages.push(step(&id, "spawn_agent", json!({ "goal": i })));
            messages.push(result_for(&id));
        }
        assert_eq!(
            outcome_of(messages, R1Config::default()).outcome,
            Outcome::Allow
        );
    }
}
