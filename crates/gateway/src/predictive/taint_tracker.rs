//! Lethal trifecta taint tracker (AFT-TAINT-LETHAL-001).
//!
//! The "lethal trifecta" is: tool with shell access + untrusted input from
//! the web + high-capability model. If all three co-occur in a single agent
//! run, the risk of prompt injection leading to RCE is significantly elevated.
//!
//! The tracker maintains a per-tenant taint state across spans in the same
//! trace. When taint reaches the LETHAL threshold it emits
//! `Decision::Warn { aft_id: "AFT-TAINT-LETHAL-001" }`.
//!
//! Taint sources (add 1 point each):
//! - Tool name contains: bash, shell, exec, eval, run_command, python, node
//! - Span has `tracelane.untrusted_input = true` (set by SDK on web-sourced spans)
//! - Model tier is frontier: claude-opus-*, gpt-5*, gemini-3-pro
//!
//! V1 ships the per-request taint scoring below as a live signature; the
//! cross-span DashMap taint accumulator (per-trace, with TTL) is a scaffold gated
//! behind an entitlement flag.

use super::{Decision, PredictiveContext, Predictor};

const LETHAL_THRESHOLD: u8 = 3;

const SHELL_TOOL_PATTERNS: &[&str] = &[
    "bash",
    "shell",
    "exec",
    "eval",
    "run_command",
    "python",
    "node",
    "cmd",
    "powershell",
];

const FRONTIER_MODEL_PATTERNS: &[&str] =
    &["claude-opus", "gpt-5", "gemini-3-pro", "gemini-3.1-pro"];

pub struct TaintTracker;

impl TaintTracker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for TaintTracker {
    fn name(&self) -> &'static str {
        "taint-tracker"
    }

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let req = ctx.request_json;
        let mut taint: u8 = 0;

        // Shell-access tool
        if let Some(tool_name) = req.get("tool_name").and_then(|v| v.as_str()) {
            let lower = tool_name.to_lowercase();
            if SHELL_TOOL_PATTERNS.iter().any(|p| lower.contains(p)) {
                taint += 1;
            }
        }

        // Untrusted input flag
        if req
            .get("tracelane_untrusted_input")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            taint += 1;
        }

        // Frontier model
        if let Some(model) = req.get("model").and_then(|v| v.as_str()) {
            let lower = model.to_lowercase();
            if FRONTIER_MODEL_PATTERNS.iter().any(|p| lower.contains(p)) {
                taint += 1;
            }
        }

        if taint >= LETHAL_THRESHOLD {
            tracing::warn!(taint_score = taint, "lethal trifecta threshold reached");
            Decision::Warn {
                aft_id: "AFT-TAINT-LETHAL-001",
            }
        } else {
            Decision::Allow
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

    #[test]
    fn trifecta_triggers_warn() {
        let tracker = TaintTracker::new();
        let req = json!({
            "tool_name": "bash",
            "tracelane_untrusted_input": true,
            "model": "claude-opus-4-7"
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(
            tracker.evaluate(&ctx),
            Decision::Warn {
                aft_id: "AFT-TAINT-LETHAL-001"
            }
        );
    }

    #[test]
    fn two_taint_sources_is_ok() {
        let tracker = TaintTracker::new();
        let req = json!({ "tool_name": "bash", "tracelane_untrusted_input": true });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(tracker.evaluate(&ctx), Decision::Allow);
    }
}
