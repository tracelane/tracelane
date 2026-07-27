//! R4 — Lethal-trifecta taint tracking (the guardrail spec §3 R4). The
//! flagship differentiator: block when **private-data access**, **untrusted
//! content**, and **exfiltration capability** converge in one tainted session
//! (EchoLeak-class; OWASP LLM01+02+06; Meta "Agents Rule of Two").
//!
//! Engine (state machine reconstructed from the request's conversation, §3 R4):
//!   1. Untrusted ingress → `tainted`: any untrusted `rag_context` chunk, or any
//!      `tool_result` whose originating tool `SEES_UNTRUSTED_CONTENT`.
//!   2. Private read → `private_data_read`: any `tool_result` whose originating
//!      tool `READS_PRIVATE_DATA`.
//!   3. Exfil egress: a proposed `tool_call` whose tool `CAN_EXFILTRATE`. If the
//!      trifecta is met (per strictness) → **block** (or warn+gate in approve
//!      mode).
//!   4. UNKNOWN-capability tools are all-caps (fail-closed); when an UNKNOWN
//!      tool drives any leg the reason is `TRIFECTA_UNKNOWN_TOOL_CAPS` and a
//!      config warning is surfaced (at registry resolution time).
//!
//! Carried-in session taint ([`crate::guardrail::context::TaintState`]) seeds
//! the reconstruction so multi-turn taint persists once a session store feeds
//! it. Details carry tool **names** only — never tool content (§2.5).
//!
//! V1 simplification (logged): the legs are evaluated over the flattened
//! request context rather than a strictly-ordered hop replay — the convergence
//! of all three legs is blocked regardless of intra-request ordering (fail
//! closed). Strict per-hop ordering is a V1.1 refinement.

use std::collections::BTreeSet;

use crate::guardrail::capability::{CapabilitySet, RegistryPosture};
use crate::guardrail::context::GuardrailContext;
use crate::guardrail::outcome::{FailMode, RailError, RailOutcome, Sides, reason_codes};
use crate::guardrail::rail::{GuardrailFeature, Rail, RailFuture};

/// Enforcement mode (§3 R4 config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Hard block on a met trifecta (default).
    Block,
    /// Warn + route to a human-approval gate instead of blocking.
    Approve,
}

/// Strictness of the trifecta condition (§3 R4 config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strictness {
    /// Require untrusted + private-read + exfil (the precise lethal trifecta).
    TwoOfThree,
    /// Conservative: untrusted + exfil is enough (ignore private-read).
    UntrustedPlusExfil,
}

/// R4 configuration.
#[derive(Debug, Clone, Copy)]
pub struct R4Config {
    pub mode: EnforcementMode,
    pub strictness: Strictness,
}

impl Default for R4Config {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Block,
            strictness: Strictness::TwoOfThree,
        }
    }
}

/// R4 lethal-trifecta rail.
#[derive(Debug, Clone, Default)]
pub struct R4Trifecta {
    config: R4Config,
}

impl R4Trifecta {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_config(config: R4Config) -> Self {
        Self { config }
    }

    /// Resolve a tool's effective capabilities + whether it is an ENFORCED
    /// unknown (the fail-closed case that drives `TRIFECTA_UNKNOWN_TOOL_CAPS`).
    /// A tool referenced by a call/result but not declared in `tool_defs` falls
    /// back to the registry posture: enforcing → all-caps fail-closed;
    /// permissive → no caps (the safe default for an unconfigured workspace).
    fn lookup(ctx: &GuardrailContext<'_>, name: &str) -> (CapabilitySet, bool) {
        for td in &ctx.tool_defs {
            if td.name == name {
                return (
                    td.capability.effective(),
                    td.capability.is_enforced_unknown(),
                );
            }
        }
        match ctx.registry_posture {
            RegistryPosture::Enforcing => (CapabilitySet::all(), true),
            RegistryPosture::Permissive => (CapabilitySet::empty(), false),
        }
    }

    /// The pure evaluation core (sync, testable). Reconstructs the trifecta
    /// state from the request context and returns the outcome.
    pub fn evaluate_sync(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        // No tool calls at all → R4 has nothing to enforce.
        if ctx.tool_calls.is_empty() && ctx.tool_results.is_empty() && ctx.rag_context.is_empty() {
            return RailOutcome::not_applicable();
        }

        // Map a tool_result back to its originating tool name via tool_call_id.
        let id_to_name: std::collections::HashMap<&str, &str> =
            ctx.tool_calls.iter().map(|tc| (tc.id, tc.name)).collect();

        // ── Leg 1: untrusted ingress → tainted ──────────────────────────────
        let mut tainted = ctx.session.taint.tainted;
        let mut unknown_leg = false;
        let mut untrusted_sources: BTreeSet<String> = BTreeSet::new();
        for chunk in &ctx.rag_context {
            if chunk.provenance.is_untrusted() {
                tainted = true;
                untrusted_sources.insert(format!("rag:{}", chunk.source.unwrap_or("?")));
            }
        }

        // ── Leg 2: private read (+ untrusted from tool results) ─────────────
        let mut private_read = ctx.session.taint.private_data_read;
        let mut private_tool: Option<String> = None;
        for result in &ctx.tool_results {
            let name = result
                .tool_call_id
                .and_then(|id| id_to_name.get(id).copied());
            let (caps, unknown) = match name {
                Some(n) => Self::lookup(ctx, n),
                // A tool result with no resolvable originating call → treat per
                // the registry posture (same safe-default rule as lookup).
                None => match ctx.registry_posture {
                    RegistryPosture::Enforcing => (CapabilitySet::all(), true),
                    RegistryPosture::Permissive => (CapabilitySet::empty(), false),
                },
            };
            let label = name.unwrap_or("tool_result").to_string();
            if caps.contains(CapabilitySet::SEES_UNTRUSTED_CONTENT) {
                tainted = true;
                untrusted_sources.insert(format!("tool:{label}"));
                unknown_leg |= unknown;
            }
            if caps.contains(CapabilitySet::READS_PRIVATE_DATA) {
                private_read = true;
                private_tool.get_or_insert(label.clone());
                unknown_leg |= unknown;
            }
        }

        // ── Leg 3: exfil-capable proposed tool call ─────────────────────────
        let mut exfil_tool: Option<String> = None;
        let mut exfil_unknown = false;
        for call in &ctx.tool_calls {
            let (caps, unknown) = Self::lookup(ctx, call.name);
            if caps.contains(CapabilitySet::CAN_EXFILTRATE) {
                exfil_tool = Some(call.name.to_string());
                exfil_unknown = unknown;
                break;
            }
        }

        let Some(exfil) = exfil_tool else {
            // No exfil capability in play → nothing to converge.
            return RailOutcome::allow();
        };

        // Trifecta condition per strictness.
        let met = match self.config.strictness {
            Strictness::TwoOfThree => tainted && private_read,
            Strictness::UntrustedPlusExfil => tainted,
        };
        if !met {
            return RailOutcome::allow();
        }

        let unknown_involved = unknown_leg || exfil_unknown;
        let reason = if unknown_involved {
            reason_codes::TRIFECTA_UNKNOWN_TOOL_CAPS
        } else {
            reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION
        };

        // Bounded, content-free details — tool NAMES + sources only (§2.5).
        let details = serde_json::json!({
            "legs": {
                "untrusted": untrusted_sources.into_iter().collect::<Vec<_>>(),
                "private_read": private_tool,
                "exfil": exfil,
            },
            "strictness": match self.config.strictness {
                Strictness::TwoOfThree => "two_of_three",
                Strictness::UntrustedPlusExfil => "untrusted_plus_exfil",
            },
            "unknown_tool_involved": unknown_involved,
            // The capability-registry mode in effect for this verdict.
            "registry_posture": ctx.registry_posture.as_str(),
        });

        match self.config.mode {
            EnforcementMode::Block => RailOutcome::block(reason).with_details(details),
            // Approve mode: warn + (the human-approval gate is wired by the
            // caller off the warn outcome).
            EnforcementMode::Approve => RailOutcome::warn(reason).with_details(details),
        }
    }
}

impl Rail for R4Trifecta {
    fn name(&self) -> &'static str {
        "R4_trifecta"
    }

    fn policy_version(&self) -> &'static str {
        "r4@1"
    }

    fn sides(&self) -> Sides {
        // V1 reconstructs the trifecta from the request conversation (incl. a
        // proposed exfil call already present in the request history), so R4 is
        // request-side. Response-side egress enforcement — catching a NEWLY
        // proposed exfil tool call in the model's streamed response — needs
        // response tool-call parsing and is a V1.1 enhancement (logged).
        Sides::RequestOnly
    }

    fn fail_mode(&self) -> FailMode {
        FailMode::Closed
    }

    fn feature(&self) -> Option<GuardrailFeature> {
        Some(GuardrailFeature::R4Trifecta)
    }

    fn evaluate<'a>(&'a self, ctx: &'a GuardrailContext<'a>) -> RailFuture<'a> {
        Box::pin(async move { Ok::<_, RailError>(self.evaluate_sync(ctx)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::CapabilityRegistry;
    use crate::guardrail::context::SessionState;
    use crate::guardrail::outcome::Outcome;
    use serde_json::json;
    use tracelane_shared::{
        ChatRequest, ContentPart, Message, MessageContent, Role, TenantId, Tool,
    };
    use ulid::Ulid;
    use uuid::Uuid;

    /// Registry with the three canonical agent tools tagged.
    fn registry() -> CapabilityRegistry {
        let mut reg = CapabilityRegistry::new();
        reg.register("web_fetch", CapabilitySet::SEES_UNTRUSTED_CONTENT);
        reg.register("db_query", CapabilitySet::READS_PRIVATE_DATA);
        reg.register("send_email", CapabilitySet::CAN_EXFILTRATE);
        reg
    }

    fn tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(format!("{name} tool")),
            input_schema: json!({ "type": "object" }),
        }
    }

    fn assistant_tool_use(id: &str, name: &str) -> Message {
        Message {
            role: Role::Assistant,
            content: MessageContent::Parts(vec![ContentPart::ToolUse {
                id: id.to_string(),
                name: name.to_string(),
                input: json!({}),
            }]),
            tool_call_id: None,
            tool_calls: None,
        }
    }

    fn tool_result(id: &str, content: &str) -> Message {
        Message {
            role: Role::Tool,
            content: MessageContent::Text(content.to_string()),
            tool_call_id: Some(id.to_string()),
            tool_calls: None,
        }
    }

    /// Build a request with the given messages + the three declared tools.
    fn request(messages: Vec<Message>, declare: &[&str]) -> ChatRequest {
        ChatRequest {
            model: "claude-sonnet-4-6".to_string(),
            system: None,
            messages,
            tools: Some(declare.iter().map(|n| tool(n)).collect()),
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
        }
    }

    fn eval(rail: &R4Trifecta, req: &ChatRequest, reg: &CapabilityRegistry) -> RailOutcome {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(1));
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            req,
            reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        rail.evaluate_sync(&ctx)
    }

    /// POSITIVE: untrusted web-fetch result → private-db read → outbound-email
    /// call → block `TRIFECTA_EXFIL_IN_TAINTED_SESSION`; ledger explains 3 legs.
    #[test]
    fn trifecta_converges_blocks() {
        let reg = registry();
        let req = request(
            vec![
                assistant_tool_use("c1", "web_fetch"),
                tool_result("c1", "<external html>"),
                assistant_tool_use("c2", "db_query"),
                tool_result("c2", "user records"),
                assistant_tool_use("c3", "send_email"),
            ],
            &["web_fetch", "db_query", "send_email"],
        );
        let out = eval(&R4Trifecta::new(), &req, &reg);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(
            out.reason_code,
            Some(reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION)
        );
        // Ledger explains the 3 legs (names only, no content).
        assert_eq!(out.details["legs"]["exfil"], "send_email");
        assert_eq!(out.details["legs"]["private_read"], "db_query");
        assert!(
            out.details["legs"]["untrusted"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "tool:web_fetch")
        );
        // No raw tool content leaked into details.
        assert!(!out.details.to_string().contains("user records"));
        assert!(!out.details.to_string().contains("external html"));
    }

    /// NO FALSE POSITIVE: same sequence WITHOUT the untrusted ingress → allowed.
    #[test]
    fn no_untrusted_ingress_allows() {
        let reg = registry();
        let req = request(
            vec![
                // db read (private) + email (exfil), but NO untrusted content.
                assistant_tool_use("c2", "db_query"),
                tool_result("c2", "user records"),
                assistant_tool_use("c3", "send_email"),
            ],
            &["web_fetch", "db_query", "send_email"],
        );
        let out = eval(&R4Trifecta::new(), &req, &reg);
        assert_eq!(
            out.outcome,
            Outcome::Allow,
            "no taint → no trifecta → allow"
        );
    }

    /// Untrusted + exfil but NO private read → allowed under two-of-three.
    #[test]
    fn untrusted_and_exfil_without_private_read_allows_two_of_three() {
        let reg = registry();
        let req = request(
            vec![
                assistant_tool_use("c1", "web_fetch"),
                tool_result("c1", "<external html>"),
                assistant_tool_use("c3", "send_email"),
            ],
            &["web_fetch", "db_query", "send_email"],
        );
        let out = eval(&R4Trifecta::new(), &req, &reg);
        assert_eq!(out.outcome, Outcome::Allow);
    }

    /// …but the conservative `UntrustedPlusExfil` strictness blocks it.
    #[test]
    fn untrusted_plus_exfil_strictness_blocks_without_private_read() {
        let reg = registry();
        let req = request(
            vec![
                assistant_tool_use("c1", "web_fetch"),
                tool_result("c1", "<external html>"),
                assistant_tool_use("c3", "send_email"),
            ],
            &["web_fetch", "db_query", "send_email"],
        );
        let rail = R4Trifecta::with_config(R4Config {
            mode: EnforcementMode::Block,
            strictness: Strictness::UntrustedPlusExfil,
        });
        let out = eval(&rail, &req, &reg);
        assert_eq!(out.outcome, Outcome::Block);
    }

    /// UNKNOWN tool in the exfil position within a tainted+private session →
    /// block `TRIFECTA_UNKNOWN_TOOL_CAPS`.
    #[test]
    fn unknown_exfil_tool_blocks_with_unknown_reason() {
        let reg = registry(); // does NOT register "mystery_exfil"
        let req = request(
            vec![
                assistant_tool_use("c1", "web_fetch"),
                tool_result("c1", "<external html>"),
                assistant_tool_use("c2", "db_query"),
                tool_result("c2", "user records"),
                assistant_tool_use("c3", "mystery_exfil"), // undeclared → UNKNOWN → all caps
            ],
            &["web_fetch", "db_query"], // mystery_exfil NOT declared
        );
        let out = eval(&R4Trifecta::new(), &req, &reg);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(
            out.reason_code,
            Some(reason_codes::TRIFECTA_UNKNOWN_TOOL_CAPS)
        );
        assert_eq!(out.details["unknown_tool_involved"], true);
    }

    /// Approve mode → warn + gate instead of a hard block.
    #[test]
    fn approve_mode_warns_instead_of_blocks() {
        let reg = registry();
        let req = request(
            vec![
                assistant_tool_use("c1", "web_fetch"),
                tool_result("c1", "<external html>"),
                assistant_tool_use("c2", "db_query"),
                tool_result("c2", "user records"),
                assistant_tool_use("c3", "send_email"),
            ],
            &["web_fetch", "db_query", "send_email"],
        );
        let rail = R4Trifecta::with_config(R4Config {
            mode: EnforcementMode::Approve,
            strictness: Strictness::TwoOfThree,
        });
        let out = eval(&rail, &req, &reg);
        assert_eq!(out.outcome, Outcome::Warn);
        assert_eq!(
            out.reason_code,
            Some(reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION)
        );
    }

    /// SAFE DEFAULT: a permissive (empty/unconfigured) registry must NOT block
    /// even the full trifecta pattern — unregistered tools hold no caps, so a
    /// workspace that hasn't configured a registry is never blocked en masse.
    #[test]
    fn permissive_registry_does_not_block_unconfigured_traffic() {
        let reg = CapabilityRegistry::new(); // EMPTY → permissive
        let req = request(
            vec![
                assistant_tool_use("c1", "web_fetch"),
                tool_result("c1", "<external html>"),
                assistant_tool_use("c2", "db_query"),
                tool_result("c2", "user records"),
                assistant_tool_use("c3", "send_email"),
            ],
            &[], // declare nothing → every tool is unregistered → permissive
        );
        let out = eval(&R4Trifecta::new(), &req, &reg);
        assert_eq!(
            out.outcome,
            Outcome::Allow,
            "permissive registry must not block an unconfigured workspace"
        );
    }

    /// …but once the workspace opts into enforcement (registry non-empty), the
    /// same unregistered-tool pattern blocks (fail-closed) with the UNKNOWN
    /// reason, and the verdict records the enforcing posture.
    #[test]
    fn enforcing_registry_blocks_unregistered_trifecta_and_records_posture() {
        let mut reg = CapabilityRegistry::new();
        reg.register("some_known_tool", CapabilitySet::empty()); // → enforcing
        let req = request(
            vec![
                assistant_tool_use("c1", "web_fetch"),
                tool_result("c1", "<external html>"),
                assistant_tool_use("c2", "db_query"),
                tool_result("c2", "user records"),
                assistant_tool_use("c3", "send_email"),
            ],
            &[], // all undeclared → enforced-unknown → all caps
        );
        let out = eval(&R4Trifecta::new(), &req, &reg);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(
            out.reason_code,
            Some(reason_codes::TRIFECTA_UNKNOWN_TOOL_CAPS)
        );
        assert_eq!(out.details["registry_posture"], "enforcing");
    }

    /// No tool calls → not_applicable (not a failure).
    #[test]
    fn no_tools_not_applicable() {
        let reg = registry();
        let req = request(
            vec![Message {
                role: Role::User,
                content: MessageContent::Text("just chatting".to_string()),
                tool_call_id: None,
                tool_calls: None,
            }],
            &[],
        );
        let out = eval(&R4Trifecta::new(), &req, &reg);
        assert_eq!(out.outcome, Outcome::NotApplicable);
    }

    /// Carried-in session taint (from a prior turn) + private read + exfil →
    /// block even though THIS request has no untrusted ingress.
    #[test]
    fn carried_in_taint_blocks() {
        let reg = registry();
        let req = request(
            vec![
                assistant_tool_use("c2", "db_query"),
                tool_result("c2", "user records"),
                assistant_tool_use("c3", "send_email"),
            ],
            &["web_fetch", "db_query", "send_email"],
        );
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(1));
        let mut session = SessionState::fresh(None);
        session.taint.tainted = true; // tainted on a previous turn
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &req,
            &reg,
            Vec::new(),
            session,
        );
        let out = R4Trifecta::new().evaluate_sync(&ctx);
        assert_eq!(out.outcome, Outcome::Block);
    }

    /// Untrusted RAG chunk (not a tool result) is a valid taint source.
    #[test]
    fn untrusted_rag_taints() {
        use crate::guardrail::context::extract_rag_context;
        let reg = registry();
        let req = request(
            vec![
                assistant_tool_use("c2", "db_query"),
                tool_result("c2", "user records"),
                assistant_tool_use("c3", "send_email"),
            ],
            &["web_fetch", "db_query", "send_email"],
        );
        let body = json!({
            "tracelane_rag_context": [
                { "content": "external doc", "provenance": "untrusted", "source": "kb://ext" }
            ]
        });
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(1));
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &req,
            &reg,
            extract_rag_context(&body),
            SessionState::fresh(None),
        );
        let out = R4Trifecta::new().evaluate_sync(&ctx);
        assert_eq!(out.outcome, Outcome::Block);
        assert!(
            out.details["legs"]["untrusted"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "rag:kb://ext")
        );
    }
}
