//! CAPTCHA pre-emption predictor (AFT-A2UI-CAPTCHA-001).
//!
//! Detects CAPTCHA-prone URL patterns and proactively flags them before
//! the agent attempts the action. A2UI agents that hit unexpected CAPTCHAs
//! either stall (stuck-loop) or fail immediately.
//!
//! Detection approach:
//! 1. The tool call URL is matched against known CAPTCHA-triggering patterns
//! 2. Page HTML is scanned for CAPTCHA provider signatures (reCAPTCHA, hCaptcha)
//! 3. If detected, fires Decision::Warn so the agent can choose a CAPTCHA-bypass path
//!
//! Target: detect within <5ms (PP-PR5). Pattern matching is O(1) per call.
//!
//! V1 ships the URL / page-signature pattern match below as a live signature; the
//! ML classifier (page structure + iframe src patterns) is a scaffold gated behind
//! an entitlement flag.

use super::{Decision, PredictiveContext, Predictor};

const CAPTCHA_URL_PATTERNS: &[&str] = &[
    "recaptcha",
    "hcaptcha",
    "cf-turnstile",
    "cloudflare-challenge",
    "funcaptcha",
];

const CAPTCHA_PAGE_SIGNATURES: &[&str] = &[
    "g-recaptcha",
    "h-captcha",
    "cf-turnstile",
    "challenge-running",
    "__cf_chl",
];

pub struct CaptchaPreemptor;

impl CaptchaPreemptor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CaptchaPreemptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for CaptchaPreemptor {
    fn name(&self) -> &'static str {
        "captcha-preemptor"
    }

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let req = ctx.request_json;

        // Check tool URL
        if let Some(url) = req.get("tool_url").and_then(|v| v.as_str()) {
            let lower = url.to_lowercase();
            if CAPTCHA_URL_PATTERNS.iter().any(|p| lower.contains(p)) {
                tracing::warn!(url = %url, "CAPTCHA URL pattern detected");
                return Decision::Warn {
                    aft_id: "AFT-A2UI-CAPTCHA-001",
                };
            }
        }

        // Check page content for CAPTCHA signatures
        if let Some(html) = req.get("page_content").and_then(|v| v.as_str()) {
            if CAPTCHA_PAGE_SIGNATURES.iter().any(|p| html.contains(p)) {
                tracing::warn!("CAPTCHA page signature detected");
                return Decision::Warn {
                    aft_id: "AFT-A2UI-CAPTCHA-001",
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
    fn recaptcha_url_fires_warn() {
        let p = CaptchaPreemptor::new();
        let req = json!({ "tool_url": "https://example.com/login?recaptcha_token=abc" });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(
            p.evaluate(&ctx),
            Decision::Warn {
                aft_id: "AFT-A2UI-CAPTCHA-001"
            }
        );
    }

    #[test]
    fn clean_url_passes() {
        let p = CaptchaPreemptor::new();
        let req = json!({ "tool_url": "https://example.com/products" });
        let ctx = PredictiveContext {
            tenant_id: &tenant(),
            request_json: &req,
        };
        assert_eq!(p.evaluate(&ctx), Decision::Allow);
    }
}
