//! R5 — Output format / schema enforcement (the guardrail spec §3 R5):
//! malformed outputs crashing downstream consumers (OWASP LLM05).
//!
//! When the request declared a JSON output format (OpenAI `response_format`
//! `json_object` / `json_schema`, surfaced as [`ExpectedFormat`]), R5 validates
//! the accumulated response: it must parse as JSON (`FORMAT_INVALID_JSON`) and,
//! if a JSON Schema was declared, satisfy it (`FORMAT_SCHEMA_FAIL`, reusing the
//! verified `predictive::tool_schema_validator::validate_call` core). No
//! declared format → `not_applicable`. Response-side, fail **OPEN-LOUD**: a
//! format failure is recorded but the response still proceeds (a `warn`, not a
//! block) — a malformed body is the model's problem to surface, not ours to
//! drop.
//!
//! **V1 scope:** R5 detects + warns. The spec's bounded ≤1 reask is a
//! buffered-path / V1.1 affordance (a streamed response cannot be un-yielded and
//! re-asked), documented here so the warn-and-record behaviour is not mistaken
//! for the full reask loop. `FORMAT_REGEX_FAIL` / `FORMAT_REASK_EXHAUSTED`
//! reason codes are reserved for that work.

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::outcome::{FailMode, RailError, RailOutcome, Sides, reason_codes};
use crate::guardrail::rail::{GuardrailFeature, Rail, RailFuture};

/// R5 output format / schema enforcement (gated `R5Format`).
#[derive(Debug, Clone, Default)]
pub struct R5Format;

impl R5Format {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate_sync(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        let (Some(fmt), Some(buf)) = (ctx.expected_format, ctx.response_buf) else {
            return RailOutcome::not_applicable();
        };
        if !fmt.json {
            return RailOutcome::not_applicable();
        }
        let text = buf.accumulated().trim();
        if text.is_empty() {
            // Nothing to validate yet (stream just started) — not a failure.
            return RailOutcome::not_applicable();
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            return RailOutcome::warn(reason_codes::FORMAT_INVALID_JSON);
        };
        if let Some(schema) = &fmt.schema {
            let violations =
                crate::predictive::tool_schema_validator::validate_call("response", schema, &value);
            if !violations.is_empty() {
                return RailOutcome::warn(reason_codes::FORMAT_SCHEMA_FAIL)
                    .with_details(serde_json::json!({ "violations": violations.len() }));
            }
        }
        RailOutcome::allow()
    }
}

impl Rail for R5Format {
    fn name(&self) -> &'static str {
        "R5_format"
    }
    fn policy_version(&self) -> &'static str {
        "r5@1"
    }
    fn sides(&self) -> Sides {
        Sides::ResponseOnly
    }
    fn fail_mode(&self) -> FailMode {
        FailMode::OpenLoud
    }
    fn feature(&self) -> Option<GuardrailFeature> {
        Some(GuardrailFeature::R5Format)
    }
    fn evaluate<'a>(&'a self, ctx: &'a GuardrailContext<'a>) -> RailFuture<'a> {
        Box::pin(async move { Ok::<_, RailError>(self.evaluate_sync(ctx)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::context::{ExpectedFormat, ResponseBuffer, ResponseInputs};
    use crate::guardrail::outcome::Outcome;
    use tracelane_shared::TenantId;
    use ulid::Ulid;
    use uuid::Uuid;

    fn inputs(fmt: Option<ExpectedFormat>) -> ResponseInputs {
        ResponseInputs {
            tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(5)),
            api_key_id: None,
            correlation_id: Ulid::from_parts(1, 1),
            system_prompt: None,
            model: "claude-sonnet-4-6".to_string(),
            session: crate::guardrail::context::SessionState::fresh(None),
            actor: "apikey:r5".to_string(),
            expected_format: fmt,
        }
    }

    fn outcome(fmt: Option<ExpectedFormat>, body: &str) -> RailOutcome {
        let inp = inputs(fmt);
        let mut buf = ResponseBuffer::new();
        buf.push_chunk(body);
        let ctx = GuardrailContext::from_response(&inp, &buf, None);
        R5Format::new().evaluate_sync(&ctx)
    }

    #[test]
    fn valid_json_allows() {
        let o = outcome(
            Some(ExpectedFormat {
                json: true,
                schema: None,
            }),
            r#"{"answer": 42}"#,
        );
        assert_eq!(o.outcome, Outcome::Allow);
    }

    #[test]
    fn invalid_json_warns_fail_open() {
        let o = outcome(
            Some(ExpectedFormat {
                json: true,
                schema: None,
            }),
            "{ not valid json",
        );
        // Fail-open-loud: a warn (response still proceeds), recorded.
        assert_eq!(o.outcome, Outcome::Warn);
        assert_eq!(o.reason_code, Some(reason_codes::FORMAT_INVALID_JSON));
    }

    #[test]
    fn schema_violation_warns() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["name"],
            "properties": { "name": { "type": "string" } }
        });
        let o = outcome(
            Some(ExpectedFormat {
                json: true,
                schema: Some(schema),
            }),
            r#"{"age": 7}"#, // missing required "name"
        );
        assert_eq!(o.outcome, Outcome::Warn);
        assert_eq!(o.reason_code, Some(reason_codes::FORMAT_SCHEMA_FAIL));
    }

    #[test]
    fn no_declared_format_is_not_applicable() {
        assert_eq!(outcome(None, "anything").outcome, Outcome::NotApplicable);
    }

    #[test]
    fn text_format_is_not_applicable() {
        let o = outcome(
            Some(ExpectedFormat {
                json: false,
                schema: None,
            }),
            "free text",
        );
        assert_eq!(o.outcome, Outcome::NotApplicable);
    }
}
