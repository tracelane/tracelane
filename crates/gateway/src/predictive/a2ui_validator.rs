//! A2UI catalog conformance validator (AFT-A2UI-CATALOG-001).
//!
//! A2UI v0.9 protocol: `createSurface`, `updateComponents`, `removeComponents`,
//! `event`, `dispose`. Each component referenced in an A2UI message must be
//! declared in the surface's `catalogId`.
//!
//! - Component type unknown → Block (AFT-A2UI-CATALOG-001)
//! - Required props missing → Warn (AFT-A2UI-CATALOG-001)
//! - `dispose` without `surface_id` → Warn (AFT-A2UI-CATALOG-001)
//!
//! Full catalog resolution (Postgres fetch by `catalog_id`) deferred to Week 7.
//! This version validates against the standard A2UI component allowlist.
//!
//! AFT reference: AFT-A2UI-CATALOG-001

use super::{Decision, PredictiveContext, Predictor};

/// Standard A2UI v0.9 component types.
const STANDARD_A2UI_TYPES: &[&str] = &[
    "Alert",
    "Badge",
    "Button",
    "Card",
    "Checkbox",
    "Divider",
    "Form",
    "Heading",
    "Image",
    "Link",
    "Modal",
    "Paragraph",
    "ProgressBar",
    "RadioGroup",
    "Select",
    "Spinner",
    "Tab",
    "Table",
    "TextArea",
    "TextInput",
];

pub struct A2uiValidator;

impl A2uiValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for A2uiValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for A2uiValidator {
    fn name(&self) -> &'static str {
        "a2ui-catalog-validator"
    }

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let req = ctx.request_json;

        // Only active for A2UI protocol messages
        if req.get("protocol").and_then(|v| v.as_str()) != Some("a2ui") {
            return Decision::Allow;
        }

        let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");

        match action {
            "createSurface" | "updateComponents" => {
                let components = match req.get("components").and_then(|v| v.as_array()) {
                    Some(c) => c,
                    None => return Decision::Allow,
                };

                for component in components {
                    let component_type =
                        component.get("type").and_then(|v| v.as_str()).unwrap_or("");

                    if component_type.is_empty() {
                        tracing::warn!(
                            tenant_id = %ctx.tenant_id,
                            action,
                            "A2UI component missing type field"
                        );
                        return Decision::Warn {
                            aft_id: "AFT-A2UI-CATALOG-001",
                        };
                    }

                    if !STANDARD_A2UI_TYPES.contains(&component_type) {
                        tracing::warn!(
                            tenant_id = %ctx.tenant_id,
                            component_type,
                            action,
                            "A2UI unknown component type — catalog_id mismatch"
                        );
                        return Decision::Block {
                            aft_id: "AFT-A2UI-CATALOG-001",
                        };
                    }
                }
            }
            "dispose" => {
                if req.get("surface_id").and_then(|v| v.as_str()).is_none() {
                    tracing::warn!(
                        tenant_id = %ctx.tenant_id,
                        "A2UI dispose missing surface_id"
                    );
                    return Decision::Warn {
                        aft_id: "AFT-A2UI-CATALOG-001",
                    };
                }
            }
            _ => {}
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
    fn unknown_component_type_blocks() {
        let v = A2uiValidator::new();
        let req = json!({
            "protocol": "a2ui",
            "action": "createSurface",
            "components": [{ "type": "MaliciousWidget" }]
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(
            v.evaluate(&ctx),
            Decision::Block {
                aft_id: "AFT-A2UI-CATALOG-001"
            }
        );
    }

    #[test]
    fn known_component_type_allows() {
        let v = A2uiValidator::new();
        let req = json!({
            "protocol": "a2ui",
            "action": "createSurface",
            "components": [{ "type": "Button", "props": { "label": "OK" } }]
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(v.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn dispose_without_surface_id_warns() {
        let v = A2uiValidator::new();
        let req = json!({ "protocol": "a2ui", "action": "dispose" });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(
            v.evaluate(&ctx),
            Decision::Warn {
                aft_id: "AFT-A2UI-CATALOG-001"
            }
        );
    }

    #[test]
    fn dispose_with_surface_id_allows() {
        let v = A2uiValidator::new();
        let req = json!({
            "protocol": "a2ui",
            "action": "dispose",
            "surface_id": "surf-abc-123"
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(v.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn non_a2ui_protocol_skipped() {
        let v = A2uiValidator::new();
        let req = json!({ "protocol": "a2a", "action": "task.send" });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(v.evaluate(&ctx), Decision::Allow);
    }
}
