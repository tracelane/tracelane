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
//! **V1 scope (deliberate, not a gap).** This rail performs request- and
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
use crate::guardrail::outcome::{FailMode, RailError, RailOutcome, Sides, reason_codes};
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
    pub fn evaluate_sync(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        if let Some(buf) = ctx.response_buf {
            let mut findings = Findings::default();
            findings.absorb(&(self.scan)(buf.accumulated()));
            return findings.into_outcome();
        }
        self.scan_request(ctx)
    }

    fn scan_request(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        let mut findings = Findings::default();
        if let Some(sys) = ctx.system_prompt {
            findings.absorb(&(self.scan)(sys));
        }
        for m in ctx.messages {
            match &m.content {
                MessageContent::Text(s) => findings.absorb(&(self.scan)(s)),
                MessageContent::Parts(parts) => {
                    for p in parts {
                        match p {
                            ContentPart::Text { text, .. } => findings.absorb(&(self.scan)(text)),
                            ContentPart::ToolResult { content, .. } => {
                                findings.absorb(&(self.scan)(content));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        findings.into_outcome()
    }
}

/// Per-category hit counts over the scanned text. Only R2-scope categories are
/// tallied — `ipv4`/`ipv6` are detected by the policy core but out of R2 scope
/// (no R2 reason code), so they do not drive the verdict.
#[derive(Debug, Default)]
struct Findings {
    secret: usize,
    card: usize,
    ssn: usize,
    email: usize,
    phone: usize,
    iban: usize,
}

impl Findings {
    fn absorb(&mut self, r: &ReversibleRedaction) {
        for e in &r.entries {
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
                _ => {} // ipv4 / ipv6 — out of R2 scope
            }
        }
    }

    fn total(&self) -> usize {
        self.secret + self.card + self.ssn + self.email + self.phone + self.iban
    }

    /// Aggregate to a verdict. Reason code is the most-severe class present
    /// (secret > card > ssn > iban > email > phone). `details` carries COUNTS
    /// and category names only — never the secret/PII values (§2.5).
    fn into_outcome(self) -> RailOutcome {
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
        } else if self.email > 0 {
            reason_codes::PII_EMAIL
        } else {
            reason_codes::PII_PHONE
        };
        RailOutcome::redact(reason).with_details(serde_json::json!({
            "has_secret": self.secret > 0,
            "counts": {
                "secret": self.secret,
                "credit_card": self.card,
                "ssn": self.ssn,
                "email": self.email,
                "phone": self.phone,
                "iban": self.iban,
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
            model: "claude-sonnet-4-6".to_string(),
            system,
            messages,
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
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
}
