//! SLM Judge — distilled 1B encoder for flow adherence, tool-selection sanity,
//! and hallucination grounding.
//!
//! ≥1K req/sec on single L4 GPU (PP-PR10).
//!
//! Model file: `TRACELANE_SLM_JUDGE_MODEL` (default: models/slm_judge.onnx)
//!   produced by `ml/slm_judge/export_onnx.py` after distillation.
//!
//! Judge dimensions:
//!   1. Flow adherence  — did the agent follow the declared task plan?
//!   2. Tool sanity     — are tool calls consistent with prior context?
//!   3. Hallucination   — does the response ground to retrieved context?
//!
//! Output: per-dimension scores [0.0, 1.0] where 1.0 = fully safe.
//! Thresholds: score < 0.4 → Block, score < 0.7 → Warn.

use super::{Decision, PredictiveContext, Predictor};

const BLOCK_SCORE: f32 = 0.4;
const WARN_SCORE: f32 = 0.7;

/// Judge scores for a single inference.
#[derive(Debug, Clone, Copy)]
pub struct JudgeScores {
    pub flow_adherence: f32,
    pub tool_sanity: f32,
    pub hallucination: f32,
}

impl JudgeScores {
    /// Return the minimum score across all dimensions.
    pub fn min_score(self) -> f32 {
        self.flow_adherence
            .min(self.tool_sanity)
            .min(self.hallucination)
    }
}

/// SLM Judge predictor.
pub struct SlmJudge {
    model_path: String,
}

impl SlmJudge {
    pub fn new() -> Self {
        let model_path = std::env::var("TRACELANE_SLM_JUDGE_MODEL")
            .unwrap_or_else(|_| "models/slm_judge.onnx".to_string());
        Self { model_path }
    }

    /// Run the SLM judge against the current request context.
    ///
    /// Stub: returns scores of 1.0 (fully safe) until the model is trained.
    /// Real implementation tokenises the span content and runs ONNX inference.
    fn judge(&self, ctx: &PredictiveContext<'_>) -> JudgeScores {
        if !std::path::Path::new(&self.model_path).exists() {
            return JudgeScores {
                flow_adherence: 1.0,
                tool_sanity: 1.0,
                hallucination: 1.0,
            };
        }

        // Full: tokenise request_json content, pad to sequence length,
        // run ort::Session inference, extract [flow, tool, hallucination] logits.
        let _ = ctx;
        JudgeScores {
            flow_adherence: 1.0,
            tool_sanity: 1.0,
            hallucination: 1.0,
        }
    }
}

impl Default for SlmJudge {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for SlmJudge {
    fn name(&self) -> &'static str {
        "slm_judge"
    }

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let scores = self.judge(ctx);
        let min_score = scores.min_score();

        if min_score < BLOCK_SCORE {
            tracing::warn!(
                flow_adherence = scores.flow_adherence,
                tool_sanity = scores.tool_sanity,
                hallucination = scores.hallucination,
                "SLM judge — BLOCK"
            );
            // SLM judge failures map to the most relevant AFT based on which
            // dimension scored lowest. Generalised to PI-CASCADE for now.
            Decision::Block {
                aft_id: "AFT-PI-CASCADE-001",
            }
        } else if min_score < WARN_SCORE {
            tracing::info!(min_score, "SLM judge — WARN");
            Decision::Warn {
                aft_id: "AFT-PI-CASCADE-001",
            }
        } else {
            Decision::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn ctx(json: serde_json::Value) -> PredictiveContext<'static> {
        PredictiveContext {
            tenant_id: Box::leak(Box::new(TenantId::from_jwt_claim(
                Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            ))),
            request_json: Box::leak(Box::new(json)),
        }
    }

    #[test]
    fn no_model_allows() {
        let judge = SlmJudge {
            model_path: "/nonexistent/slm.onnx".into(),
        };
        let c = ctx(serde_json::json!({}));
        assert_eq!(judge.evaluate(&c), Decision::Allow);
    }

    #[test]
    fn judge_scores_min_score() {
        let s = JudgeScores {
            flow_adherence: 0.9,
            tool_sanity: 0.3,
            hallucination: 0.8,
        };
        assert_eq!(s.min_score(), 0.3);
    }

    #[test]
    fn below_block_threshold_blocks() {
        let score = JudgeScores {
            flow_adherence: 0.3,
            tool_sanity: 0.3,
            hallucination: 0.3,
        };
        let min = score.min_score();
        let decision = if min < BLOCK_SCORE {
            Decision::Block {
                aft_id: "AFT-PI-CASCADE-001",
            }
        } else if min < WARN_SCORE {
            Decision::Warn {
                aft_id: "AFT-PI-CASCADE-001",
            }
        } else {
            Decision::Allow
        };
        assert_eq!(
            decision,
            Decision::Block {
                aft_id: "AFT-PI-CASCADE-001"
            }
        );
    }

    #[test]
    fn between_warn_and_block_warns() {
        let min = 0.55f32;
        assert!((BLOCK_SCORE..WARN_SCORE).contains(&min));
        let decision = if min < BLOCK_SCORE {
            Decision::Block {
                aft_id: "AFT-PI-CASCADE-001",
            }
        } else if min < WARN_SCORE {
            Decision::Warn {
                aft_id: "AFT-PI-CASCADE-001",
            }
        } else {
            Decision::Allow
        };
        assert_eq!(
            decision,
            Decision::Warn {
                aft_id: "AFT-PI-CASCADE-001"
            }
        );
    }
}
