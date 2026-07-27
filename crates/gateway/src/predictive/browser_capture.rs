//! Browser passive observer — DOM state tracker and mutation scorer.
//!
//! The full Playwright + rrweb enrichment lives in the ingest worker
//! (`crates/ingest/src/browser_enricher.rs`) and is a scaffold gated behind an
//! entitlement flag. This gateway-side
//! predictor reads the enriched `tracelane.browser.*` span attributes
//! emitted upstream and makes fast inline decisions (<5ms).
//!
//! Decision logic:
//! - `captcha_detected == true` → Warn (AFT-A2UI-CAPTCHA-001)
//! - `dom_mutation_score == 0.0` AND `step_index > 1` → Warn (AFT-A2UI-STUCKLOOP-001)
//! - Otherwise → Allow
//!
//! The ingest worker flow (scaffold, gated behind an entitlement flag):
//! 1. Agent SDK emits browser spans with `tracelane.browser.*` attributes.
//! 2. Ingest worker attaches `screenshot_url`, `dom_hash`, `dom_mutation_score`.
//! 3. This predictor reads those attributes on the next gateway request.
//!
//! AFT references: AFT-A2UI-STUCKLOOP-001, AFT-A2UI-CAPTCHA-001

use super::{Decision, PredictiveContext, Predictor};

pub struct BrowserPassiveObserver;

impl BrowserPassiveObserver {
    pub fn new() -> Self {
        Self
    }

    fn get_bool(req: &serde_json::Value, dotted: &str, underscored: &str) -> Option<bool> {
        req.get(dotted)
            .or_else(|| req.get(underscored))
            .and_then(|v| v.as_bool())
    }

    fn get_u64(req: &serde_json::Value, dotted: &str, underscored: &str) -> Option<u64> {
        req.get(dotted)
            .or_else(|| req.get(underscored))
            .and_then(|v| v.as_u64())
    }

    fn get_f64(req: &serde_json::Value, dotted: &str, underscored: &str) -> Option<f64> {
        req.get(dotted)
            .or_else(|| req.get(underscored))
            .and_then(|v| v.as_f64())
    }
}

impl Default for BrowserPassiveObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for BrowserPassiveObserver {
    fn name(&self) -> &'static str {
        "browser-passive-observer"
    }

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let req = ctx.request_json;

        // Only active when browser capture attributes are present
        let has_step_index = req
            .get("tracelane.browser.step_index")
            .or_else(|| req.get("tracelane_browser_step_index"))
            .is_some();
        if !has_step_index {
            return Decision::Allow;
        }

        // CAPTCHA detection takes priority
        if Self::get_bool(
            req,
            "tracelane.browser.captcha_detected",
            "tracelane_browser_captcha_detected",
        )
        .unwrap_or(false)
        {
            tracing::warn!(
                tenant_id = %ctx.tenant_id,
                "CAPTCHA detected by browser passive observer — recommend human handoff"
            );
            return Decision::Warn {
                aft_id: "AFT-A2UI-CAPTCHA-001",
            };
        }

        let step_index = Self::get_u64(
            req,
            "tracelane.browser.step_index",
            "tracelane_browser_step_index",
        )
        .unwrap_or(0);

        // DOM mutation score stuck-loop (only meaningful after first step)
        if step_index > 1 {
            let mutation_score = Self::get_f64(
                req,
                "tracelane.browser.dom_mutation_score",
                "tracelane_browser_dom_mutation_score",
            )
            .unwrap_or(1.0); // default assume change if attr absent

            if mutation_score == 0.0 {
                tracing::warn!(
                    tenant_id = %ctx.tenant_id,
                    step_index,
                    mutation_score,
                    "DOM mutation score zero — browser agent may be stuck"
                );
                return Decision::Warn {
                    aft_id: "AFT-A2UI-STUCKLOOP-001",
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
    fn no_browser_attrs_skipped() {
        let obs = BrowserPassiveObserver::new();
        let req = json!({ "model": "claude-sonnet-4-6", "messages": [] });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(obs.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn captcha_detected_warns() {
        let obs = BrowserPassiveObserver::new();
        let req = json!({
            "tracelane_browser_step_index": 3u64,
            "tracelane_browser_captcha_detected": true
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(
            obs.evaluate(&ctx),
            Decision::Warn {
                aft_id: "AFT-A2UI-CAPTCHA-001"
            }
        );
    }

    #[test]
    fn zero_mutation_score_warns_after_step_1() {
        let obs = BrowserPassiveObserver::new();
        let req = json!({
            "tracelane_browser_step_index": 4u64,
            "tracelane_browser_dom_mutation_score": 0.0
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(
            obs.evaluate(&ctx),
            Decision::Warn {
                aft_id: "AFT-A2UI-STUCKLOOP-001"
            }
        );
    }

    #[test]
    fn first_step_zero_mutation_allowed() {
        let obs = BrowserPassiveObserver::new();
        let req = json!({
            "tracelane_browser_step_index": 1u64,
            "tracelane_browser_dom_mutation_score": 0.0
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        // step_index == 1: first action, no prior state to compare
        assert_eq!(obs.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn positive_mutation_score_allows() {
        let obs = BrowserPassiveObserver::new();
        let req = json!({
            "tracelane_browser_step_index": 5u64,
            "tracelane_browser_dom_mutation_score": 0.42
        });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(obs.evaluate(&ctx), Decision::Allow);
    }
}
