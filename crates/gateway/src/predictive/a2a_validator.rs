//! A2A handoff schema validator (AFT-A2A-LIFECYCLE-001).
//!
//! Validates that A2A (Agent-to-Agent) handoff messages conform to the
//! expected schema. A2A handoffs carry a structured payload with:
//! - `handoff_id`: UUID v7
//! - `from_agent`: source agent name
//! - `to_agent`: destination agent name
//! - `context`: shared context object
//! - `capabilities`: list of capabilities the receiving agent must have
//!
//! If the handoff payload is malformed or missing required fields,
//! fires `Decision::Warn { aft_id: "AFT-A2A-LIFECYCLE-001" }`.
//!
//! V1 ships the required-field check below as a live signature; full JSON Schema
//! validation (via the `jsonschema` crate) is a scaffold gated behind an
//! entitlement flag.

use super::{Decision, PredictiveContext, Predictor};

const REQUIRED_A2A_FIELDS: &[&str] = &["handoff_id", "from_agent", "to_agent", "context"];

pub struct A2aValidator;

impl A2aValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for A2aValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for A2aValidator {
    fn name(&self) -> &'static str {
        "a2a-validator"
    }

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let req = ctx.request_json;

        // Only validate if this is an A2A handoff message
        let is_a2a = req
            .get("tracelane_message_type")
            .and_then(|v| v.as_str())
            .map(|t| t == "a2a_handoff")
            .unwrap_or(false);

        if !is_a2a {
            return Decision::Allow;
        }

        let handoff = match req.get("a2a_handoff") {
            Some(h) => h,
            None => {
                tracing::warn!("A2A handoff message missing 'a2a_handoff' field");
                return Decision::Warn {
                    aft_id: "AFT-A2A-LIFECYCLE-001",
                };
            }
        };

        for field in REQUIRED_A2A_FIELDS {
            if handoff.get(field).is_none() {
                tracing::warn!(missing_field = %field, "A2A handoff schema violation");
                return Decision::Warn {
                    aft_id: "AFT-A2A-LIFECYCLE-001",
                };
            }
        }

        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }

    #[test]
    fn non_a2a_message_is_allowed() {
        let validator = A2aValidator::new();
        let req = json!({ "model": "claude-sonnet-4-6" });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(validator.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn valid_handoff_is_allowed() {
        let validator = A2aValidator::new();
        let req = json!({
            "tracelane_message_type": "a2a_handoff",
            "a2a_handoff": {
                "handoff_id": "018f1234-5678-7abc-def0-123456789abc",
                "from_agent": "planner",
                "to_agent": "executor",
                "context": { "task": "search web" }
            }
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(validator.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn missing_field_triggers_warn() {
        let validator = A2aValidator::new();
        let req = json!({
            "tracelane_message_type": "a2a_handoff",
            "a2a_handoff": {
                "handoff_id": "018f1234-5678-7abc-def0-123456789abc",
                "from_agent": "planner"
                // missing to_agent and context
            }
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(
            validator.evaluate(&ctx),
            Decision::Warn {
                aft_id: "AFT-A2A-LIFECYCLE-001"
            }
        );
    }
}
