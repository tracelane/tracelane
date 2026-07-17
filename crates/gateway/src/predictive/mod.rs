//! Predictive guardrail layer — evaluates every request against all enabled predictors.
//!
//! Each predictor detects a specific AFT failure mode (see `spec/aft-1/`).
//! The layer returns the most severe `Decision` across all predictors.
//! Blocking short-circuits evaluation; warnings accumulate.
//!
//! Predictors are wired in via `PredictiveLayer::new()` as they are implemented.

pub mod a2a_validator;
pub mod a2ui_validator;
pub mod browser_capture;
pub mod captcha;
pub mod mcp_hash_watcher;
pub mod pr8_lite_argument_drift;
pub mod prompt_guard;
pub mod prompt_injection;
pub mod slm_judge;
pub mod stuck_loop;
pub mod taint_tracker;
pub mod tool_definition_drift;
pub mod tool_schema_validator;
pub mod trajectory_guard;

use a2a_validator::A2aValidator;
use a2ui_validator::A2uiValidator;
use browser_capture::BrowserPassiveObserver;
use captcha::CaptchaPreemptor;
use mcp_hash_watcher::McpHashWatcher;
use pr8_lite_argument_drift::Pr8LiteArgumentDrift;
use prompt_guard::PromptGuardPredictor;
use prompt_injection::PromptInjectionDetector;
use slm_judge::SlmJudge;
use stuck_loop::StuckLoopDetector;
use taint_tracker::TaintTracker;
use tool_definition_drift::ToolDefinitionDrift;
use tool_schema_validator::ToolSchemaValidator;
use tracelane_shared::TenantId;
use trajectory_guard::TrajectoryGuard;

/// Predictive layer decision returned by every predictor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Warn { aft_id: &'static str },
    Block { aft_id: &'static str },
}

/// All predictors implement this trait.
///
/// A11: `evaluate_async` is the canonical hot-path entry. The default
/// impl forwards to the sync `evaluate` so existing predictors don't
/// need to change. Predictors that genuinely need async work (e.g.
/// `PromptGuardPredictor` calling an ONNX sidecar over HTTP) override
/// `evaluate_async` directly and skip the sync path — removing the
/// previous `block_in_place(Handle::current().block_on(...))` dance
/// that panicked on current-thread runtimes and serialized
/// concurrency.
pub trait Predictor: Send + Sync {
    fn name(&self) -> &'static str;

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision;

    /// Async hot-path entry. Default forwards to the sync `evaluate`.
    fn evaluate_async<'a>(
        &'a self,
        ctx: &'a PredictiveContext<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Decision> + Send + 'a>> {
        Box::pin(async move { self.evaluate(ctx) })
    }
}

/// Context passed to every predictor on each request.
pub struct PredictiveContext<'a> {
    pub tenant_id: &'a TenantId,
    pub request_json: &'a serde_json::Value,
}

/// Runs all enabled predictors in sequence.
/// Returns the most severe Decision across all predictors.
pub struct PredictiveLayer {
    predictors: Vec<Box<dyn Predictor>>,
    /// Operational kill-switch (ADR-038). When a predictor's
    /// `kill.predictive.<name>` flag is set, that predictor is skipped
    /// fleet-wide without a redeploy. `None` in contexts with no flag layer.
    kill_switch: Option<std::sync::Arc<crate::kill_switch::KillSwitch>>,
}

impl PredictiveLayer {
    pub fn new() -> Self {
        let mut predictors: Vec<Box<dyn Predictor>> = vec![
            Box::new(McpHashWatcher::new()),
            // ADR-024 §1 item 2 (tool-definition-drift half): catches a tool
            // that keeps its name but mutates its schema/description — the
            // silent rug-pull the name-set hash and PR13 both miss.
            Box::new(ToolDefinitionDrift::new()),
            Box::new(TaintTracker::new()),
            Box::new(StuckLoopDetector::new()),
            Box::new(BrowserPassiveObserver::new()),
            Box::new(PromptInjectionDetector::new()),
            Box::new(A2aValidator::new()),
            Box::new(A2uiValidator::new()),
            Box::new(CaptchaPreemptor::new()),
            // arg-drift detector. Default extractor is bag-of-bytes — full
            // PR8 swaps in MiniLM via ort once the model is exported.
            Box::new(Pr8LiteArgumentDrift::new()),
            // PR13 (ADR-024 §3): hallucinated tool-call schema validator.
            // Pure/stateless — validates request-side tool calls against the
            // request's declared tool schemas. Warn-only (observe-first).
            Box::new(ToolSchemaValidator::new()),
        ];

        // PR6: Llama Prompt Guard 2 22M ONNX sidecar bridge.
        // Threshold 0.5 is the model's default; tune per FT-05 eval.
        //
        // Opus-rereview M-5: on init failure, the predictor is OMITTED
        // from the stack (rather than silently substituted with
        // PromptInjectionDetector, which has a different detection
        // surface). PromptInjectionDetector is already pushed above,
        // so injection coverage is preserved either way. The error log
        // surfaces explicitly so operators can fix the sidecar config.
        match PromptGuardPredictor::new(0.5) {
            Ok(p) => predictors.push(Box::new(p)),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "tracelane.predictive.degraded=true — PromptGuardPredictor init FAILED, PR6 (Llama Prompt Guard 2) is OFFLINE. \
                     Stack continues with the remaining predictors; FT-05 fail-open semantics apply.",
                );
            }
        }

        // Tier 2 predictors (Week 8 ML models): ONNX Runtime inference
        // Both are no-ops until model files are trained and placed in models/
        predictors.push(Box::new(TrajectoryGuard::new()));
        predictors.push(Box::new(SlmJudge::new()));

        Self {
            predictors,
            kill_switch: None,
        }
    }

    /// Attach the operational kill-switch so `kill.predictive.<name>` can
    /// disable a predictor fleet-wide (ADR-038).
    #[must_use]
    pub fn with_kill_switch(
        mut self,
        kill_switch: std::sync::Arc<crate::kill_switch::KillSwitch>,
    ) -> Self {
        self.kill_switch = Some(kill_switch);
        self
    }

    /// Is this predictor disabled by `kill.predictive.<name>`?
    fn is_killed(&self, name: &str) -> bool {
        self.kill_switch
            .as_ref()
            .is_some_and(|ks| ks.predictive_killed(name))
    }
}

impl PredictiveLayer {
    /// Legacy sync entry — kept so existing tests and the few callers
    /// that have no Tokio runtime context still compile. The hot path
    /// in `server.rs::chat_completions_handler` uses `evaluate_async`.
    #[tracing::instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id))]
    pub fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let mut result = Decision::Allow;
        for predictor in &self.predictors {
            if self.is_killed(predictor.name()) {
                continue;
            }
            // FT-05: a panicking predictor (e.g. ONNX Runtime OOM / corrupt
            // model) must NOT take the gateway down. Catch the unwind and
            // fail OPEN — false-negatives on a guardrail are strictly better
            // strategy makes this catchable for Rust-level panics.
            let d =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| predictor.evaluate(ctx)))
                    .unwrap_or_else(|_| Self::degraded_fail_open(predictor.name()));
            result = Self::more_severe(result, d);
            if matches!(result, Decision::Block { .. }) {
                break;
            }
        }
        result
    }

    /// A11: async hot-path entry. Each predictor's `evaluate_async`
    /// is awaited in turn (short-circuiting on Block) so an async
    /// predictor (PromptGuardPredictor) no longer needs
    /// `block_in_place` to call its sidecar.
    #[tracing::instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id))]
    pub async fn evaluate_async(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let mut result = Decision::Allow;
        for predictor in &self.predictors {
            if self.is_killed(predictor.name()) {
                continue;
            }
            // FT-05 fail-open, async hot path: catch a panic from the
            // predictor's future (ONNX sidecar bridge, etc.) and degrade to
            // Allow rather than propagating the panic up the request task.
            use futures::FutureExt;
            let d = std::panic::AssertUnwindSafe(predictor.evaluate_async(ctx))
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Self::degraded_fail_open(predictor.name()));
            result = Self::more_severe(result, d);
            if matches!(result, Decision::Block { .. }) {
                break;
            }
        }
        result
    }

    /// FT-05 fail-open landing pad: a predictor panicked. Emit the degraded
    /// alert span and return `Allow` so the request proceeds. The
    /// `tracelane.predictive.degraded=true` marker is what the SLO dashboard
    fn degraded_fail_open(predictor_name: &'static str) -> Decision {
        tracing::error!(
            predictor = predictor_name,
            "tracelane.predictive.degraded=true — predictor PANICKED; failing OPEN (FT-05). \
             The request proceeds as if this predictor returned Allow; the gateway does NOT 503.",
        );
        Decision::Allow
    }

    fn more_severe(a: Decision, b: Decision) -> Decision {
        match (&a, &b) {
            (Decision::Block { .. }, _) => a,
            (_, Decision::Block { .. }) => b,
            (Decision::Warn { .. }, _) => a,
            (_, Decision::Warn { .. }) => b,
            _ => a,
        }
    }
}

impl Default for PredictiveLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    /// A predictor that always panics — stands in for an ONNX Runtime crash
    /// (OOM, corrupt model file) on the FT-05 fail-open path.
    struct PanickingPredictor;

    impl Predictor for PanickingPredictor {
        fn name(&self) -> &'static str {
            "panicking-test-predictor"
        }

        fn evaluate(&self, _ctx: &PredictiveContext<'_>) -> Decision {
            panic!("simulated ONNX Runtime crash (FT-05)");
        }
        // evaluate_async uses the default forward to `evaluate`, so the
        // panic also fires on the async hot path.
    }

    fn panicking_layer() -> PredictiveLayer {
        // Construct directly with the private fields (in-module test) so the
        // only predictor in the stack is the panicking one.
        PredictiveLayer {
            predictors: vec![Box::new(PanickingPredictor)],
            kill_switch: None,
        }
    }

    /// FT-05: a panicking predictor must not propagate out of the sync entry
    /// point — the layer catches the unwind and fails OPEN (Decision::Allow).
    #[test]
    fn ft05_panicking_predictor_fails_open_sync() {
        let layer = panicking_layer();
        let tid = TenantId::from_jwt_claim(Uuid::from_u128(0xF705));
        let req = serde_json::json!({"messages": []});
        let ctx = PredictiveContext {
            tenant_id: &tid,
            request_json: &req,
        };
        assert_eq!(
            layer.evaluate(&ctx),
            Decision::Allow,
            "panicking predictor must fail open, not panic",
        );
    }

    /// FT-05: same guarantee on the async hot path (`evaluate_async`), which
    /// is what `server.rs` actually drives per request.
    #[tokio::test]
    async fn ft05_panicking_predictor_fails_open_async() {
        let layer = panicking_layer();
        let tid = TenantId::from_jwt_claim(Uuid::from_u128(0xF705));
        let req = serde_json::json!({"messages": []});
        let ctx = PredictiveContext {
            tenant_id: &tid,
            request_json: &req,
        };
        assert_eq!(
            layer.evaluate_async(&ctx).await,
            Decision::Allow,
            "panicking predictor must fail open on the async hot path too",
        );
    }
}
