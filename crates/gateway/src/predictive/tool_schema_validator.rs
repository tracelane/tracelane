//!
//! Pure, stateless validation of the tool calls a request carries against the
//! tool schemas that same request *declared*. In an agentic loop the request
//! replays the conversation — including the assistant's prior `tool_calls`
//! (and `tool_use` content parts) — so the gateway can catch the two dominant
//! tool-failure modes on the request *before* the orchestrator dispatches the
//! next turn:
//!   1. a tool name the request never declared (hallucinated tool), and
//!   2. arguments that don't conform to the declared JSON-Schema — a missing
//!      `required` field, a wrong primitive type, or (when the schema sets
//!      `additionalProperties: false`) an unexpected field.
//!
//! The canonical postmortem shape (ADR-024 §3): the agent calls
//! `lookup_order(email=…)` when the schema requires `order_id`.
//!
//! No new infra, no state, no network. It evaluates a JSON-Schema *subset*
//! (top-level `type` / `required` / `properties` / `additionalProperties`)
//! over `serde_json::Value`, which covers the common hallucination shapes
//! without pulling a full JSON-Schema engine onto the hot path. Nested-object
//! schemas are intentionally not recursed — top-level checks are deterministic
//!
//! Decision: observe-first `Warn { aft_id: "AFT-TOOL-SCHEMA-001" }`. The
//! gateway is a proxy — a schema violation is a strong signal but blocking a
//! call whose tool may be declared out-of-band would break legitimate flows.
//! ADR-024's "structured 400 so the agent self-corrects" is enforcement and is
//! left to an opt-in policy layer; the telemetry signal ships first.

use serde_json::Value;
use tracing::instrument;

use super::{Decision, PredictiveContext, Predictor};

/// AFT-1 failure-mode id for a hallucinated / schema-violating tool call.
pub const AFT_TOOL_SCHEMA: &str = "AFT-TOOL-SCHEMA-001";

/// A single schema violation found on a tool call. Carries only structural
/// metadata (tool name, field name, type names) — never argument *values*, so
/// it is safe to log without leaking secrets into spans (CLAUDE.md §Security).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCallViolation {
    /// The call names a tool the request never declared.
    UnknownTool { call: String },
    /// The schema expects an object but the arguments are some other JSON type.
    ArgumentsNotObject { call: String },
    /// A `required` field declared by the schema is absent from the arguments.
    MissingRequired { call: String, field: String },
    /// A present field's JSON type does not match the schema's declared type.
    TypeMismatch {
        call: String,
        field: String,
        expected: String,
    },
    /// `additionalProperties: false` and the arguments carry an undeclared key.
    UnexpectedField { call: String, field: String },
}

/// One declared tool call extracted from a request message.
struct ExtractedCall {
    name: String,
    input: Value,
}

/// Predictor implementing PR13 hallucinated tool-call schema validation.
pub struct ToolSchemaValidator;

impl ToolSchemaValidator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ToolSchemaValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Does `value` satisfy a JSON-Schema `type` token (a string, or an array of
/// strings interpreted as a union)? Unknown / absent type tokens pass — we only
/// reject a *declared* type that is contradicted.
fn type_matches(schema_type: &Value, value: &Value) -> bool {
    match schema_type {
        Value::String(t) => primitive_matches(t, value),
        Value::Array(types) => types
            .iter()
            .filter_map(Value::as_str)
            .any(|t| primitive_matches(t, value)),
        // No `type` declared (or a non-string/array) — nothing to contradict.
        _ => true,
    }
}

fn primitive_matches(type_name: &str, value: &Value) -> bool {
    match type_name {
        "string" => value.is_string(),
        "number" => value.is_number(),
        // JSON-Schema `integer`: a number with no fractional part.
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        // Unknown type keyword — don't manufacture a violation.
        _ => true,
    }
}

/// Validate one tool call's `input` against its declared `input_schema`,
/// appending any violations found. Top-level checks only (see module docs).
fn validate_one(call: &str, schema: &Value, input: &Value, out: &mut Vec<ToolCallViolation>) {
    // A schema is "object-shaped" if it says so, or carries object keywords.
    let object_shaped = schema.get("type").and_then(Value::as_str) == Some("object")
        || schema.get("properties").is_some()
        || schema.get("required").is_some();

    if !object_shaped {
        // Non-object top-level schema (rare for tools) — only a declared-type
        // contradiction is meaningful.
        if let Some(t) = schema.get("type") {
            if !type_matches(t, input) {
                out.push(ToolCallViolation::TypeMismatch {
                    call: call.to_owned(),
                    field: "<root>".to_owned(),
                    expected: t.to_string(),
                });
            }
        }
        return;
    }

    let Some(args) = input.as_object() else {
        out.push(ToolCallViolation::ArgumentsNotObject {
            call: call.to_owned(),
        });
        return;
    };

    // 1. required fields present
    if let Some(req) = schema.get("required").and_then(Value::as_array) {
        for field in req.iter().filter_map(Value::as_str) {
            if !args.contains_key(field) {
                out.push(ToolCallViolation::MissingRequired {
                    call: call.to_owned(),
                    field: field.to_owned(),
                });
            }
        }
    }

    let properties = schema.get("properties").and_then(Value::as_object);

    // 2. present fields type-check against their declared property schema
    if let Some(props) = properties {
        for (field, sub) in props {
            if let (Some(declared), Some(actual)) = (sub.get("type"), args.get(field)) {
                if !type_matches(declared, actual) {
                    out.push(ToolCallViolation::TypeMismatch {
                        call: call.to_owned(),
                        field: field.clone(),
                        expected: declared.to_string(),
                    });
                }
            }
        }
    }

    // 3. additionalProperties:false → no undeclared keys
    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
        for field in args.keys() {
            let declared = properties.is_some_and(|p| p.contains_key(field));
            if !declared {
                out.push(ToolCallViolation::UnexpectedField {
                    call: call.to_owned(),
                    field: field.clone(),
                });
            }
        }
    }
}

/// Collect every tool call carried by the request's `messages` — both the
/// `message.tool_calls[]` array form and `content[].type == "tool_use"` parts.
fn extract_calls(request: &Value) -> Vec<ExtractedCall> {
    let mut calls = Vec::new();
    let Some(messages) = request.get("messages").and_then(Value::as_array) else {
        return calls;
    };
    for msg in messages {
        if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
            for tc in tcs {
                if let Some(name) = tc.get("name").and_then(Value::as_str) {
                    calls.push(ExtractedCall {
                        name: name.to_owned(),
                        input: tc.get("input").cloned().unwrap_or(Value::Null),
                    });
                }
            }
        }
        if let Some(parts) = msg.get("content").and_then(Value::as_array) {
            for part in parts {
                if part.get("type").and_then(Value::as_str) == Some("tool_use") {
                    if let Some(name) = part.get("name").and_then(Value::as_str) {
                        calls.push(ExtractedCall {
                            name: name.to_owned(),
                            input: part.get("input").cloned().unwrap_or(Value::Null),
                        });
                    }
                }
            }
        }
    }
    calls
}

/// Validate every tool call in `request` against the request's declared
/// `tools[].input_schema`. Returns all violations found (empty = clean).
///
/// Returns early-empty when the request declares no tools — without a declared
/// schema there is nothing to validate against, so the validator stays silent
/// rather than guessing.
pub fn validate_request(request: &Value) -> Vec<ToolCallViolation> {
    let mut violations = Vec::new();

    let Some(tools) = request.get("tools").and_then(Value::as_array) else {
        return violations;
    };
    if tools.is_empty() {
        return violations;
    }

    // name -> input_schema for declared tools.
    let mut schemas: std::collections::HashMap<&str, &Value> = std::collections::HashMap::new();
    for tool in tools {
        if let Some(name) = tool.get("name").and_then(Value::as_str) {
            let schema = tool.get("input_schema").unwrap_or(&Value::Null);
            schemas.insert(name, schema);
        }
    }

    for call in extract_calls(request) {
        match schemas.get(call.name.as_str()) {
            None => violations.push(ToolCallViolation::UnknownTool { call: call.name }),
            Some(schema) => validate_one(&call.name, schema, &call.input, &mut violations),
        }
    }

    violations
}

/// Validate one tool call's `input` against its declared `schema`, returning the
/// violations (empty = clean). Public so the guardrail **R3** rail reuses this
/// verified validation core on typed `ToolDef`/`ToolCall` data instead of
/// re-deriving schema checks (run-doc: "VERIFY existing schema-validation still
/// fires; ADD definition-pinning").
#[must_use]
pub fn validate_call(name: &str, schema: &Value, input: &Value) -> Vec<ToolCallViolation> {
    let mut violations = Vec::new();
    validate_one(name, schema, input, &mut violations);
    violations
}

impl Predictor for ToolSchemaValidator {
    fn name(&self) -> &'static str {
        "tool-schema-validator"
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id))]
    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let violations = validate_request(ctx.request_json);
        if violations.is_empty() {
            return Decision::Allow;
        }

        // ADR-024 §3 telemetry: emit `tool.schema_violation` with the
        // structural detail only (tool + field + violation kind) — never the
        // argument values, which may carry secrets.
        tracing::warn!(
            target: "tool.schema_violation",
            aft_id = AFT_TOOL_SCHEMA,
            violation_count = violations.len(),
            violations = ?violations,
            "tracelane.tool_call.schema_violation=true — request carries a tool call \
             that does not conform to its declared tool schema (PR13)",
        );

        Decision::Warn {
            aft_id: AFT_TOOL_SCHEMA,
        }
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

    fn ctx<'a>(tid: &'a TenantId, req: &'a Value) -> PredictiveContext<'a> {
        PredictiveContext {
            tenant_id: tid,
            request_json: req,
        }
    }

    /// The ADR-024 §3 canonical case: schema requires `order_id`, the agent
    /// hallucinated `email`. Both the missing required field and (under a
    /// closed schema) the unexpected field must surface.
    #[test]
    fn adr_canonical_lookup_order_email_instead_of_order_id() {
        let req = json!({
            "tools": [{
                "name": "lookup_order",
                "input_schema": {
                    "type": "object",
                    "properties": { "order_id": { "type": "string" } },
                    "required": ["order_id"],
                    "additionalProperties": false
                }
            }],
            "messages": [{
                "role": "assistant",
                "tool_calls": [{ "id": "c1", "name": "lookup_order", "input": { "email": "a@b.co" } }]
            }]
        });
        let v = validate_request(&req);
        assert!(v.contains(&ToolCallViolation::MissingRequired {
            call: "lookup_order".into(),
            field: "order_id".into(),
        }));
        assert!(v.contains(&ToolCallViolation::UnexpectedField {
            call: "lookup_order".into(),
            field: "email".into(),
        }));
    }

    #[test]
    fn conforming_call_is_allowed() {
        let req = json!({
            "tools": [{
                "name": "lookup_order",
                "input_schema": {
                    "type": "object",
                    "properties": { "order_id": { "type": "string" } },
                    "required": ["order_id"]
                }
            }],
            "messages": [{
                "role": "assistant",
                "tool_calls": [{ "id": "c1", "name": "lookup_order", "input": { "order_id": "A-100" } }]
            }]
        });
        assert!(validate_request(&req).is_empty());
        assert_eq!(
            ToolSchemaValidator::new().evaluate(&ctx(&tenant(), &req)),
            Decision::Allow
        );
    }

    #[test]
    fn unknown_tool_name_is_flagged() {
        let req = json!({
            "tools": [{ "name": "lookup_order", "input_schema": { "type": "object" } }],
            "messages": [{
                "role": "assistant",
                "tool_calls": [{ "id": "c1", "name": "delete_everything", "input": {} }]
            }]
        });
        assert_eq!(
            validate_request(&req),
            vec![ToolCallViolation::UnknownTool {
                call: "delete_everything".into()
            }]
        );
    }

    #[test]
    fn wrong_primitive_type_is_flagged() {
        let req = json!({
            "tools": [{
                "name": "set_qty",
                "input_schema": {
                    "type": "object",
                    "properties": { "qty": { "type": "integer" } },
                    "required": ["qty"]
                }
            }],
            "messages": [{
                "role": "assistant",
                "tool_calls": [{ "id": "c1", "name": "set_qty", "input": { "qty": "twelve" } }]
            }]
        });
        let v = validate_request(&req);
        assert_eq!(v.len(), 1);
        assert!(matches!(
            &v[0],
            ToolCallViolation::TypeMismatch { call, field, .. } if call == "set_qty" && field == "qty"
        ));
    }

    #[test]
    fn integer_rejects_float_but_accepts_whole() {
        assert!(primitive_matches("integer", &json!(12)));
        assert!(!primitive_matches("integer", &json!(12.5)));
        assert!(primitive_matches("number", &json!(12.5)));
    }

    #[test]
    fn union_type_accepts_any_member() {
        let schema = json!({
            "type": "object",
            "properties": { "id": { "type": ["string", "integer"] } }
        });
        let mut out = Vec::new();
        validate_one("t", &schema, &json!({ "id": 7 }), &mut out);
        assert!(out.is_empty());
        validate_one("t", &schema, &json!({ "id": "x" }), &mut out);
        assert!(out.is_empty());
        validate_one("t", &schema, &json!({ "id": 1.5 }), &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn arguments_not_object_is_flagged() {
        let req = json!({
            "tools": [{ "name": "t", "input_schema": { "type": "object", "required": ["x"] } }],
            "messages": [{
                "role": "assistant",
                "tool_calls": [{ "id": "c1", "name": "t", "input": "not-an-object" }]
            }]
        });
        assert_eq!(
            validate_request(&req),
            vec![ToolCallViolation::ArgumentsNotObject { call: "t".into() }]
        );
    }

    #[test]
    fn tool_use_content_part_is_validated_too() {
        // Anthropic-style content-parts form rather than tool_calls[].
        let req = json!({
            "tools": [{
                "name": "lookup_order",
                "input_schema": { "type": "object", "required": ["order_id"] }
            }],
            "messages": [{
                "role": "assistant",
                "content": [
                    { "type": "text", "text": "let me check" },
                    { "type": "tool_use", "id": "c1", "name": "lookup_order", "input": {} }
                ]
            }]
        });
        assert_eq!(
            validate_request(&req),
            vec![ToolCallViolation::MissingRequired {
                call: "lookup_order".into(),
                field: "order_id".into(),
            }]
        );
    }

    #[test]
    fn no_declared_tools_is_silent() {
        // Nothing to validate against -> Allow, never a false positive.
        let req = json!({
            "messages": [{
                "role": "assistant",
                "tool_calls": [{ "id": "c1", "name": "anything", "input": {} }]
            }]
        });
        assert!(validate_request(&req).is_empty());
        let req_empty = json!({ "tools": [], "messages": [] });
        assert!(validate_request(&req_empty).is_empty());
    }

    #[test]
    fn open_schema_does_not_flag_extra_fields() {
        // additionalProperties not set to false -> extra keys are allowed.
        let req = json!({
            "tools": [{
                "name": "search",
                "input_schema": {
                    "type": "object",
                    "properties": { "q": { "type": "string" } },
                    "required": ["q"]
                }
            }],
            "messages": [{
                "role": "assistant",
                "tool_calls": [{ "id": "c1", "name": "search", "input": { "q": "hi", "limit": 5 } }]
            }]
        });
        assert!(validate_request(&req).is_empty());
    }

    #[test]
    fn evaluate_warns_on_violation() {
        let req = json!({
            "tools": [{ "name": "t", "input_schema": { "type": "object", "required": ["x"] } }],
            "messages": [{
                "role": "assistant",
                "tool_calls": [{ "id": "c1", "name": "t", "input": {} }]
            }]
        });
        assert_eq!(
            ToolSchemaValidator::new().evaluate(&ctx(&tenant(), &req)),
            Decision::Warn {
                aft_id: AFT_TOOL_SCHEMA
            }
        );
    }
}
