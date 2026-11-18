//! R2 — Secrets + structured-PII redaction (the guardrail spec §3 R2):
//! stop secrets/structured-PII leaving to providers and returning to users
//! (OWASP LLM02).
//!
//! Detection reuses the verified `tracelane_policy::pii::redact_reversible`
//! core (one detector set, shared with the observability one-way `redact`):
//! secret prefixes (`sk-`, `ghp_`, `AKIA`, `xoxb-`, JWT, PEM, …) → fail-CLOSED
//! secret class; structured PII (Luhn-gated cards, SSN, email, E.164 phone) →
//! redact-or-warn PII class. Each hit becomes a reversible
//! `{{TL_REDACT:<category>:<idx>}}` placeholder with a per-request map for
//! response re-insertion.
//!
//! **2026-10-05 supersession:** request mutation is now enforced by `egress`,
//! and response mutation by `ResponseGuard`. Explicit PII class policies select
//! detectors/actions and literal exceptions on both sides. The historical V1
//! staging description below no longer describes the current apply seam.
//!
//! **Historical V1 scope (deliberate, not a gap).** This rail performs request- and
//! response-side **detection** and emits the redact/secret verdict to the
//! ledger. The actual outgoing-payload mutation + the per-request reversible
//! map lifecycle + response re-insertion are **one coherent seam** (the map
//! built at request time must survive to the streamed response), wired with
//! the R5/R6 SSE call-site (enforce-before-yield). Until then R2 RECORDS what
//! it would redact — the same staged posture R4 uses with the permissive
//! registry. So the §6 R2 box (acceptance: *zero secret bytes egress*) is NOT
//! ticked here. `block`-on-secret-to-a-different-provider is a config policy
//! (`[IMPL-CHOICE]`); V1 default is redact (which satisfies zero-egress once
//! the apply seam lands), so the rail returns `redact`, never `block`, on
//! detection — the only `block` path is fail-CLOSED on a detector panic
//! (`DETECTOR_ERROR`, via the dispatcher's catch_unwind seam).
//!
//! IBAN: the `PII_IBAN` reason code is reserved but the policy detector set has
//! no IBAN matcher yet (carried forward from `tracelane_policy::pii`); IBAN
//! redaction lands when that detector does. Documented, not silently dropped.

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::egress::{Leaf, egress_leaves};
use crate::guardrail::outcome::{FailMode, RailError, RailOutcome, Sides, reason_codes};
use crate::guardrail::pii_policy::PiiPolicy;
use crate::guardrail::policy::Mode;
use crate::guardrail::rail::{GuardrailFeature, Rail, RailFuture};
use tracelane_policy::pii::{ReversibleRedaction, is_secret_category, redact_reversible};
use tracelane_shared::{ContentPart, MessageContent};

/// The detector seam — `redact_reversible` in prod; swappable in tests to
/// exercise the fail-CLOSED detector-panic path.
type Scanner = fn(&str) -> ReversibleRedaction;

/// R2 secrets + structured-PII redaction (gated `R2SecretsPii`).
#[derive(Debug, Clone)]
pub struct R2SecretsPii {
    scan: Scanner,
}

impl Default for R2SecretsPii {
    fn default() -> Self {
        Self::new()
    }
}

impl R2SecretsPii {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scan: redact_reversible,
        }
    }

    /// Test-only constructor that injects the detector — used to prove the
    /// fail-CLOSED path (a panicking detector → block `DETECTOR_ERROR`).
    #[cfg(test)]
    pub(crate) fn with_scanner(scan: Scanner) -> Self {
        Self { scan }
    }

    /// Side-dispatch: a populated `response_buf` means the dispatcher is
    /// running the response side; otherwise it is the request side.
    /// The detector seam plus the policy's custom entities (GWY-63).
    ///
    /// A text with more custom matches than `custom_max_matches` comes back with
    /// `overflow` set; [`Findings`] turns that into a fail-CLOSED `DETECTOR_ERROR` block.
    fn scan_text(&self, text: &str, policy: Option<&PiiPolicy>) -> (ReversibleRedaction, bool) {
        // Custom entities first, on the raw text (as `pii_policy::scan_checked`), then the
        // detector seam over what remains. Indices here only feed the counts, never a map.
        let (pre, custom, complete) = match policy {
            Some(p) => p.custom_pass(text, 0),
            None => (text.to_owned(), Vec::new(), true),
        };
        let mut r = (self.scan)(&pre);
        r.entries.extend(custom);
        (r, !complete)
    }

    pub fn evaluate_sync(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        if let Some(buf) = ctx.response_buf {
            let mut findings = Findings::default();
            findings.absorb_scan(
                self.scan_text(buf.accumulated(), ctx.policy.pii()),
                ctx.policy.pii(),
            );
            return findings.into_outcome();
        }
        self.scan_request(ctx)
    }

    /// R2 over a request body that egresses as-is (a relay wire, a batch line, a count-tokens
    /// companion): every text leaf the egress walker hands over — keys and decoded text media
    /// included. A text payload too large to decode cannot be cleared, so it BLOCKS
    /// (`UNSCANNABLE_MEDIA`, fail-CLOSED), like a detector that could not run.
    pub(crate) fn scan_egress_json(
        &self,
        body: &serde_json::Value,
        policy: Option<&PiiPolicy>,
    ) -> RailOutcome {
        let mut findings = Findings::default();
        let unscannable = egress_leaves(body, &mut |leaf, _| match leaf {
            Leaf::Text(t) => {
                if crate::guardrail::pii_policy::contains(t, policy) {
                    findings.absorb_scan(self.scan_text(t, policy), policy);
                }
                false
            }
            Leaf::Unscannable => true,
        });
        if unscannable {
            return RailOutcome::block(reason_codes::UNSCANNABLE_MEDIA);
        }
        findings.into_outcome()
    }

    fn scan_request(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        let mut findings = Findings::default();
        // M-1: on a relay wire the caller's own JSON is what egresses, so THAT is what is
        // scanned — every text leaf minus the opaque allowlist, by the same walk that later
        // rewrites it (`egress::redact_relay_body`). The read model is lossy by design and
        // must not decide what R2 sees.
        if let Some(body) = ctx.egress_json {
            return self.scan_egress_json(body, ctx.policy.pii());
        }
        if let Some(sys) = ctx.system_prompt {
            findings.absorb_scan(self.scan_text(sys, ctx.policy.pii()), ctx.policy.pii());
        }
        for m in ctx.messages {
            match &m.content {
                MessageContent::Text(s) => {
                    findings.absorb_scan(self.scan_text(s, ctx.policy.pii()), ctx.policy.pii())
                }
                MessageContent::Parts(parts) => {
                    for p in parts {
                        match p {
                            ContentPart::Text { text, .. } => findings.absorb_scan(
                                self.scan_text(text, ctx.policy.pii()),
                                ctx.policy.pii(),
                            ),
                            ContentPart::ToolResult { content, .. } => {
                                findings.absorb_scan(
                                    self.scan_text(content, ctx.policy.pii()),
                                    ctx.policy.pii(),
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        // M-1 (C1 before it): the tool definitions and every other forwarded text — tool-call
        // arguments, `response_format`, `user`, `metadata`, extras — egress too. Many small
        // leaves (schema keywords), so the allocation-free check runs first.
        for t in ctx.tool_def_text.iter().chain(&ctx.extra_text) {
            if crate::guardrail::pii_policy::contains(t, ctx.policy.pii()) {
                findings.absorb_scan(self.scan_text(t, ctx.policy.pii()), ctx.policy.pii());
            }
        }
        findings.into_outcome()
    }
}

/// Per-category hit counts over scanned text. The legacy default excludes IP
/// detections from the verdict; an explicit class policy can select them.
#[derive(Debug, Default)]
struct Findings {
    action: Option<Mode>,
    ip: usize,
    secret: usize,
    card: usize,
    ssn: usize,
    email: usize,
    phone: usize,
    iban: usize,
    custom: usize,
    /// A text had more custom matches than the cap (fail-CLOSED).
    overflow: bool,
}

impl Findings {
    fn absorb_scan(
        &mut self,
        (r, overflow): (ReversibleRedaction, bool),
        policy: Option<&PiiPolicy>,
    ) {
        self.overflow |= overflow;
        self.absorb(&r, policy);
    }

    fn absorb(&mut self, r: &ReversibleRedaction, policy: Option<&PiiPolicy>) {
        for e in &r.entries {
            if let Some(policy) = policy {
                let Some(action) = policy.action(e) else {
                    continue;
                };
                self.action = Some(match (self.action, action) {
                    (Some(Mode::Block), _) | (_, Mode::Block) => Mode::Block,
                    (Some(Mode::Redact), _) | (_, Mode::Redact) => Mode::Redact,
                    _ => Mode::Observe,
                });
            }

            if e.category == crate::guardrail::pii_policy::CUSTOM_CATEGORY {
                self.custom += 1;
                continue;
            }
            if is_secret_category(e.category) {
                self.secret += 1;
                continue;
            }
            match e.category {
                "credit_card" => self.card += 1,
                "ssn" => self.ssn += 1,
                "email" => self.email += 1,
                "phone" => self.phone += 1,
                "iban" => self.iban += 1,
                "ipv4" | "ipv6" if policy.is_some() => self.ip += 1,
                _ => {} // ipv4 / ipv6 — out of R2 scope
            }
        }
    }

    fn total(&self) -> usize {
        self.secret
            + self.card
            + self.ssn
            + self.email
            + self.phone
            + self.iban
            + self.ip
            + self.custom
    }

    /// Aggregate to a verdict. Reason code is the most-severe class present
    /// (secret > card > ssn > iban > email > phone). `details` carries COUNTS
    /// and category names only — never the secret/PII values (§2.5).
    fn into_outcome(self) -> RailOutcome {
        if self.overflow {
            return RailOutcome::block(reason_codes::DETECTOR_ERROR);
        }
        if self.total() == 0 {
            return RailOutcome::allow();
        }
        let reason = if self.secret > 0 {
            reason_codes::SECRET_DETECTED
        } else if self.card > 0 {
            reason_codes::PII_CARD
        } else if self.ssn > 0 {
            reason_codes::PII_SSN
        } else if self.iban > 0 {
            reason_codes::PII_IBAN
        } else if self.custom > 0 {
            reason_codes::PII_CUSTOM
        } else if self.email > 0 {
            reason_codes::PII_EMAIL
        } else if self.ip > 0 {
            "PII_IP"
        } else {
            reason_codes::PII_PHONE
        };
        let outcome = match self.action {
            Some(Mode::Block) => RailOutcome::block(reason),
            Some(Mode::Observe) => RailOutcome::warn(reason),
            _ => RailOutcome::redact(reason),
        };
        outcome.with_details(serde_json::json!({
            "has_secret": self.secret > 0,
            "counts": {
                "secret": self.secret,
                "credit_card": self.card,
                "ssn": self.ssn,
                "email": self.email,
                "phone": self.phone,
                "iban": self.iban,
                "ip": self.ip,
                "custom": self.custom,
            },
            "total": self.total(),
        }))
    }
}

impl Rail for R2SecretsPii {
    fn name(&self) -> &'static str {
        "R2_secrets_pii"
    }
    fn policy_version(&self) -> &'static str {
        "r2@1"
    }
    fn sides(&self) -> Sides {
        Sides::Both
    }
    fn fail_mode(&self) -> FailMode {
        FailMode::Closed
    }
    fn feature(&self) -> Option<GuardrailFeature> {
        Some(GuardrailFeature::R2SecretsPii)
    }
    fn evaluate<'a>(&'a self, ctx: &'a GuardrailContext<'a>) -> RailFuture<'a> {
        Box::pin(async move { Ok::<_, RailError>(self.evaluate_sync(ctx)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::CapabilityRegistry;
    use crate::guardrail::context::{GuardrailContext, ResponseBuffer, SessionState};
    use crate::guardrail::outcome::Outcome;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};
    use ulid::Ulid;
    use uuid::Uuid;

    fn request(messages: Vec<Message>, system: Option<String>) -> ChatRequest {
        ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            model: "claude-sonnet-4-6".to_string(),
            system,
            messages,
            tools: None,
            tool_choice: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
            ..Default::default()
        }
    }

    fn user(text: &str) -> Message {
        Message {
            role: Role::User,
            content: MessageContent::Text(text.to_string()),
            tool_call_id: None,
            tool_calls: None,
        }
    }

    fn ctx<'r>(
        tenant: &'r TenantId,
        req: &'r ChatRequest,
        reg: &'r CapabilityRegistry,
    ) -> GuardrailContext<'r> {
        GuardrailContext::from_request(
            tenant,
            None,
            Ulid::from_parts(1, 1),
            req,
            reg,
            Vec::new(),
            SessionState::fresh(None),
        )
    }

    /// §3 R2: a secret in a prompt → redact, reason SECRET_DETECTED, has_secret.
    #[test]
    fn secret_in_prompt_redacts() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(1));
        let req = request(
            vec![user(
                "deploy with sk-abcdefghijklmnopqrstuvwxyz012345 please",
            )],
            None,
        );
        let reg = CapabilityRegistry::new();
        let out = R2SecretsPii::new().evaluate_sync(&ctx(&tenant, &req, &reg));
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::SECRET_DETECTED));
        assert_eq!(out.details["has_secret"], true);
        // The secret value never appears in the verdict details.
        assert!(!out.details.to_string().contains("sk-abcdefghijklmnop"));
    }

    /// §3 R2: a Luhn-valid card → redact PII_CARD.
    #[test]
    fn credit_card_redacts_pii_card() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(2));
        let req = request(vec![user("charge 4111 1111 1111 1111 now")], None);
        let reg = CapabilityRegistry::new();
        let out = R2SecretsPii::new().evaluate_sync(&ctx(&tenant, &req, &reg));
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::PII_CARD));
        assert_eq!(out.details["has_secret"], false);
        assert!(!out.details.to_string().contains("4111"));
    }

    /// C1 (security review 2026-10-02): a secret inside an ALLOWLISTED unmodelled field
    /// (`reasoning`, `provider`, …) is forwarded upstream, so R2 must see it too.
    #[test]
    fn c1_secret_in_an_extra_field_string_leaf_is_detected() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(9));
        let mut req = request(vec![user("hi")], None);
        req.extra.insert(
            "reasoning".into(),
            serde_json::json!({"effort": "high", "note": ["deploy with sk-abcdefghijklmnopqrstuvwxyz012345"]}),
        );
        let reg = CapabilityRegistry::new();
        let out = R2SecretsPii::new().evaluate_sync(&ctx(&tenant, &req, &reg));
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::SECRET_DETECTED));
    }

    /// Secret in the SYSTEM prompt is caught too.
    #[test]
    fn secret_in_system_prompt_redacts() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(3));
        let req = request(
            vec![user("hi")],
            Some("internal key AKIAIOSFODNN7EXAMPLE do not share".to_string()),
        );
        let reg = CapabilityRegistry::new();
        let out = R2SecretsPii::new().evaluate_sync(&ctx(&tenant, &req, &reg));
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::SECRET_DETECTED));
    }

    /// Clean prompt → allow (the rail ran, found nothing).
    #[test]
    fn clean_prompt_allows() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(4));
        let req = request(vec![user("what is the capital of France?")], None);
        let reg = CapabilityRegistry::new();
        assert_eq!(
            R2SecretsPii::new()
                .evaluate_sync(&ctx(&tenant, &req, &reg))
                .outcome,
            Outcome::Allow
        );
    }

    /// Most-severe wins: a prompt with BOTH an email and a secret → reason is
    /// SECRET_DETECTED (secret outranks PII), and both are counted.
    #[test]
    fn secret_outranks_pii_in_reason_code() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(5));
        let req = request(
            vec![user(
                "mail jane@example.com key sk-abcdefghijklmnopqrstuvwxyz0123",
            )],
            None,
        );
        let reg = CapabilityRegistry::new();
        let out = R2SecretsPii::new().evaluate_sync(&ctx(&tenant, &req, &reg));
        assert_eq!(out.reason_code, Some(reason_codes::SECRET_DETECTED));
        assert_eq!(out.details["counts"]["secret"], 1);
        assert_eq!(out.details["counts"]["email"], 1);
    }

    /// Response-side: a secret straddling the SSE-buffer lookback is detected
    /// on the accumulated buffer (the response-side detection that the R5/R6
    /// SSE wiring will enforce-before-yield).
    #[test]
    fn response_side_detects_secret_in_buffer() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(6));
        let req = request(vec![user("hi")], None);
        let reg = CapabilityRegistry::new();
        let base = ctx(&tenant, &req, &reg);
        let mut buf = ResponseBuffer::new();
        buf.push_chunk("here is the leaked AKIAIOSFODNN7EXAMPLE token");
        let with_resp = base.with_response(&buf, None);
        let out = R2SecretsPii::new().evaluate_sync(&with_resp);
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::SECRET_DETECTED));
    }

    /// Security posture: R2 is a fail-CLOSED, both-sided, gated rail.
    #[test]
    fn r2_is_fail_closed_gated_both_sides() {
        let r = R2SecretsPii::new();
        assert_eq!(r.fail_mode(), FailMode::Closed);
        assert_eq!(r.sides(), Sides::Both);
        assert_eq!(r.feature(), Some(GuardrailFeature::R2SecretsPii));
    }

    fn custom_policy(action: &str) -> crate::guardrail::policy::Policy {
        crate::guardrail::policy::Policy::parse(&serde_json::json!({"rails":{"R2_secrets_pii":{
            "pii":{"classes":{},"custom":[{"name":"employee_id","pattern":"EMP-[0-9]{6}","action":action}]}}}}))
        .expect("valid custom policy")
    }

    fn eval_custom(action: &str, text: &str) -> RailOutcome {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(63));
        let req = request(vec![user(text)], None);
        let reg = CapabilityRegistry::new();
        let mut c = ctx(&tenant, &req, &reg);
        c.policy = custom_policy(action);
        R2SecretsPii::new().evaluate_sync(&c)
    }

    #[test]
    fn gwy63_custom_entity_redacts_with_its_own_reason() {
        let out = eval_custom("redact", "badge EMP-123456 please");
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::PII_CUSTOM));
        assert_eq!(out.details["counts"]["custom"], 1);
        assert!(
            !out.details.to_string().contains("EMP-123456"),
            "no matched text in details"
        );
    }

    #[test]
    fn gwy63_custom_entity_block_and_observe_actions() {
        assert_eq!(eval_custom("block", "EMP-123456").outcome, Outcome::Block);
        assert_eq!(eval_custom("observe", "EMP-123456").outcome, Outcome::Warn);
    }

    #[test]
    fn gwy63_no_custom_match_allows() {
        assert_eq!(
            eval_custom("block", "EMP-12345 is too short").outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn gwy63_custom_entity_in_a_tool_definition_leaf_is_seen() {
        let policy = custom_policy("block");
        let body = serde_json::json!({"messages":[{"role":"user","content":"hi"}],
            "tools":[{"type":"function","function":{"name":"lookup","description":"default EMP-654321"}}]});
        let out = R2SecretsPii::new().scan_egress_json(&body, policy.pii());
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::PII_CUSTOM));
    }

    #[test]
    fn gwy63_response_side_custom_entity_is_seen() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(64));
        let req = request(vec![user("hi")], None);
        let reg = CapabilityRegistry::new();
        let mut base = ctx(&tenant, &req, &reg);
        base.policy = custom_policy("redact");
        let mut buf = ResponseBuffer::new();
        buf.push_chunk("Your id is EMP-000042.");
        let c = base.with_response(&buf, None);
        let out = R2SecretsPii::new().evaluate_sync(&c);
        assert_eq!(out.reason_code, Some(reason_codes::PII_CUSTOM));
    }

    #[test]
    fn gwy63_match_flood_fails_closed_even_under_observe() {
        // A pattern that matches everywhere must not grow one request's work without bound.
        let text = "EMP-123456 ".repeat(5_000);
        let out = eval_custom("observe", &text);
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::DETECTOR_ERROR));
    }
}
