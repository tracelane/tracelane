//! The `GuardrailVerdict` evidentiary record (the guardrail spec §2.5).
//! This is the Article-12 record written once per side. It serializes to the
//! exact §2.5 JSON contract, is appended to the universal hash-chain
//! (`recorder`), and mirrored to a queryable ClickHouse table.
//!
//! Redaction (§2.5): `details` MUST NOT carry raw secrets, full PII, or full
//! prompt text. The first line of defense is the rails themselves (they build
//! bounded, redacted detail objects). [`GuardrailVerdict::redact_in_place`] is
//! the second line — it scrubs credential byte-patterns from every rail's
//! details via the shared `redact::scrub` layer before the verdict is hashed
//! or stored.

use serde::Serialize;

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::dispatcher::{RailRecord, SideOutcome};
use crate::guardrail::outcome::{Decision, Outcome, Side};

/// Versioned schema id for the verdict wire contract (§2.5).
pub const VERDICT_SCHEMA: &str = "tracelane.guardrail.verdict.v1";

/// One rail's entry in the verdict `rails[]` array (§2.5).
#[derive(Debug, Clone, Serialize)]
pub struct RailVerdict {
    pub rail: &'static str,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<&'static str>,
    pub policy_version: &'static str,
    /// Set for the R8 ONNX model in V1.1; `None` for deterministic rails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<&'static str>,
    pub latency_micros: u64,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
}

impl RailVerdict {
    fn from_record(record: &RailRecord) -> Self {
        Self {
            rail: record.rail,
            outcome: record.outcome.outcome,
            score: record.outcome.score,
            threshold: record.outcome.threshold,
            reason_code: record.outcome.reason_code,
            policy_version: record.policy_version,
            model_version: None,
            latency_micros: record.latency_micros,
            details: record.outcome.details.clone(),
        }
    }
}

/// The full §2.5 verdict record. Field order/names match the spec exactly.
#[derive(Debug, Clone, Serialize)]
pub struct GuardrailVerdict {
    pub schema: &'static str,
    pub correlation_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub side: Side,
    pub ts_unix_nanos: i64,
    pub decision: Decision,
    pub rails: Vec<RailVerdict>,
    pub total_latency_micros: u64,
    /// Present iff any rail failed open (§2.5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fail_open_rails: Vec<&'static str>,
}

impl GuardrailVerdict {
    /// Build a verdict from a dispatched [`SideOutcome`] + the request context.
    /// `tenant_id` is the resolved UUID via [`GuardrailContext::ch_tenant_key`]
    /// — never an org_id.
    #[must_use]
    pub fn build(
        side_outcome: &SideOutcome,
        ctx: &GuardrailContext<'_>,
        ts_unix_nanos: i64,
    ) -> Self {
        Self {
            schema: VERDICT_SCHEMA,
            correlation_id: ctx.correlation_id.to_string(),
            tenant_id: ctx.ch_tenant_key(),
            workspace_id: ctx.workspace_id().as_uuid().to_string(),
            side: side_outcome.side,
            ts_unix_nanos,
            decision: side_outcome.decision,
            rails: side_outcome
                .records
                .iter()
                .map(RailVerdict::from_record)
                .collect(),
            total_latency_micros: side_outcome.total_latency_micros,
            fail_open_rails: side_outcome.fail_open_rails(),
        }
    }

    /// Defense-in-depth (§2.5): scrub credential byte-patterns from every rail's
    /// details before the verdict is hashed/stored. Rails are contractually
    /// barred from putting secrets in details; this is the second line, not the
    /// first.
    pub fn redact_in_place(&mut self) {
        for rail in &mut self.rails {
            if !rail.details.is_null() {
                redact_value(&mut rail.details);
            }
        }
    }

    /// The serialized rails array (already redacted) for the ClickHouse `rails`
    /// column. Falls back to `[]` if serialization somehow fails (never on the
    /// happy path — all fields are plain JSON).
    #[must_use]
    pub fn rails_json(&self) -> String {
        serde_json::to_string(&self.rails).unwrap_or_else(|_| "[]".to_string())
    }
}

/// Recursively scrub every string leaf of a JSON value through the shared
/// credential-redaction layer (`sk-`, `AKIA`, `AIza`, Stripe keys, bare
/// `Bearer`, JWT shapes, …). Structure is preserved; only secret-shaped byte
/// runs are replaced.
fn redact_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            let scrubbed = tracelane_shared::redact::scrub(s.as_bytes());
            *s = String::from_utf8_lossy(&scrubbed).into_owned();
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                redact_value(v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::CapabilityRegistry;
    use crate::guardrail::context::SessionState;
    use crate::guardrail::dispatcher::RailRecord;
    use crate::guardrail::outcome::{RailOutcome, reason_codes};
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};
    use ulid::Ulid;
    use uuid::Uuid;

    fn ctx_request() -> ChatRequest {
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

    fn side_outcome_with(records: Vec<RailRecord>, decision: Decision) -> SideOutcome {
        SideOutcome {
            side: Side::Request,
            decision,
            records,
            total_latency_micros: 1234,
        }
    }

    fn record(rail: &'static str, outcome: RailOutcome) -> RailRecord {
        RailRecord {
            rail,
            policy_version: "test@1",
            latency_micros: 7,
            outcome,
        }
    }

    /// §2.5 wire-shape: a verdict serializes to exactly the documented fields.
    #[test]
    fn verdict_matches_spec_shape() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(0xAA));
        let req = ctx_request();
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
        let so = side_outcome_with(
            vec![record(
                "R4_trifecta",
                RailOutcome::block(reason_codes::TRIFECTA_EXFIL_IN_TAINTED_SESSION)
                    .with_details(serde_json::json!({ "legs": 3 })),
            )],
            Decision::Block,
        );
        let verdict = GuardrailVerdict::build(&so, &ctx, 1_700_000_000_000_000_000);
        let v = serde_json::to_value(&verdict).unwrap();

        assert_eq!(v["schema"], "tracelane.guardrail.verdict.v1");
        assert_eq!(v["tenant_id"], Uuid::from_u128(0xAA).to_string());
        assert_eq!(v["side"], "request");
        assert_eq!(v["decision"], "block");
        assert_eq!(v["ts_unix_nanos"], 1_700_000_000_000_000_000_i64);
        assert_eq!(v["total_latency_micros"], 1234);
        let rail0 = &v["rails"][0];
        assert_eq!(rail0["rail"], "R4_trifecta");
        assert_eq!(rail0["outcome"], "block");
        assert_eq!(rail0["reason_code"], "TRIFECTA_EXFIL_IN_TAINTED_SESSION");
        assert_eq!(rail0["policy_version"], "test@1");
        assert_eq!(rail0["latency_micros"], 7);
        assert_eq!(rail0["details"]["legs"], 3);
        // deterministic rail → no score/threshold/model_version keys.
        assert!(rail0.get("score").is_none());
        assert!(rail0.get("model_version").is_none());
    }

    /// §2.5: `fail_open_rails` is present iff non-empty.
    #[test]
    fn fail_open_rails_present_only_when_nonempty() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(1));
        let req = ctx_request();
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

        // No fail-open → key absent.
        let clean = side_outcome_with(
            vec![record("R1_cost", RailOutcome::allow())],
            Decision::Allow,
        );
        let v = serde_json::to_value(GuardrailVerdict::build(&clean, &ctx, 0)).unwrap();
        assert!(v.get("fail_open_rails").is_none());

        // A fail-open rail → key present with the rail id.
        let failed = side_outcome_with(
            vec![record(
                "R5_format",
                RailOutcome::fail_open(reason_codes::CONFIG_MISSING),
            )],
            Decision::Allow,
        );
        let v = serde_json::to_value(GuardrailVerdict::build(&failed, &ctx, 0)).unwrap();
        assert_eq!(v["fail_open_rails"], serde_json::json!(["R5_format"]));
    }

    /// §2.5 redaction: a secret accidentally placed in details is scrubbed
    /// before the verdict is hashed/stored.
    #[test]
    fn redact_in_place_scrubs_planted_secret() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(2));
        let req = ctx_request();
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
        // A rail (mistakenly) puts a live-looking OpenAI key in details.
        let leaky = side_outcome_with(
            vec![record(
                "R2_secrets",
                RailOutcome::redact(reason_codes::SECRET_DETECTED).with_details(
                    serde_json::json!({
                        "note": "found sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 in the prompt",
                        "nested": [{ "k": "AKIAIOSFODNN7EXAMPLE" }]
                    }),
                ),
            )],
            Decision::Redact,
        );
        let mut verdict = GuardrailVerdict::build(&leaky, &ctx, 0);
        verdict.redact_in_place();
        let serialized = serde_json::to_string(&verdict).unwrap();
        assert!(
            !serialized.contains("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
            "OpenAI key must be scrubbed from details"
        );
        assert!(
            !serialized.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS key in a nested array must be scrubbed too"
        );
        // The surrounding non-secret text survives.
        assert!(serialized.contains("in the prompt"));
    }

    #[test]
    fn rails_json_is_valid_array() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(3));
        let req = ctx_request();
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
        let so = side_outcome_with(
            vec![record(
                "R1_cost",
                RailOutcome::warn(reason_codes::BUDGET_CAP),
            )],
            Decision::Warn,
        );
        let verdict = GuardrailVerdict::build(&so, &ctx, 0);
        let parsed: serde_json::Value = serde_json::from_str(&verdict.rails_json()).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed[0]["rail"], "R1_cost");
    }
}
