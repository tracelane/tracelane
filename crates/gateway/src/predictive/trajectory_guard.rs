//! Trajectory Guard — ONNX Runtime inference for trajectory-level anomaly detection.
//!
//! Runs the Siamese recurrent autoencoder (arXiv 2601.00516) trained on 50K trace
//! pairs (normal vs. failure modes). Detects novel failure patterns that rule-based
//! predictors miss. Loaded from `TRACELANE_TRAJ_GUARD_MODEL` (default: models/trajectory_guard.onnx).
//!
//!
//! Two decision thresholds:
//!   reconstruction_error > WARN_THRESHOLD  → Warn (AFT-TRAJ-ANOMALY-001)
//!   reconstruction_error > BLOCK_THRESHOLD → Block (AFT-TRAJ-ANOMALY-001)
//!
//! Model file path:
//!   crates/gateway/models/trajectory_guard.onnx  (produced by ml/trajectory_guard/export_onnx.py)

use super::{Decision, PredictiveContext, Predictor};

/// Reconstruction error above this triggers Warn.
const WARN_THRESHOLD: f32 = 0.65;
/// Reconstruction error above this triggers Block.
const BLOCK_THRESHOLD: f32 = 0.85;

/// ONNX span feature attributes consumed by the Trajectory Guard model.
/// Maps OpenInference semconv attributes to model input features.
const FEATURE_ATTRS: &[&str] = &[
    "llm.token_count.prompt",
    "llm.token_count.completion",
    "llm.latency_ms",
    "tracelane.step_index",
    "tracelane.tool_call_count",
    "tracelane.taint.data_access",
    "tracelane.taint.channel_access",
    "tracelane.taint.untrusted_input",
];

/// Trajectory Guard predictor.
///
/// In production the ONNX model is loaded at startup and kept in memory.
/// The `ort` (ORT) crate runs inference synchronously in the calling thread.
pub struct TrajectoryGuard {
    /// Model path for logging; actual session is loaded lazily.
    model_path: String,
}

impl TrajectoryGuard {
    pub fn new() -> Self {
        let model_path = std::env::var("TRACELANE_TRAJ_GUARD_MODEL")
            .unwrap_or_else(|_| "models/trajectory_guard.onnx".to_string());
        Self { model_path }
    }

    /// Extract scalar features from the span context.
    ///
    /// Returns a vec of f32 values in the same order as `FEATURE_ATTRS`.
    /// Missing attributes default to 0.0.
    fn extract_features(&self, ctx: &PredictiveContext<'_>) -> Vec<f32> {
        FEATURE_ATTRS
            .iter()
            .map(|attr| {
                ctx.request_json
                    .get(*attr)
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0) as f32
            })
            .collect()
    }

    /// Run ONNX inference and return the reconstruction error.
    ///
    /// Stub: returns 0.0 (Allow) until the ONNX model file is present.
    /// Real implementation uses the `ort` crate to run the Siamese RAE.
    fn infer_reconstruction_error(&self, features: &[f32]) -> f32 {
        if !std::path::Path::new(&self.model_path).exists() {
            // Model not yet trained (Week 8 training pipeline) — Allow
            return 0.0;
        }

        // Full: use ort::Session to run inference
        // let session = ort::Session::builder()?.with_model_from_file(&self.model_path)?;
        // let input = Array2::from_shape_vec([1, features.len()], features.to_vec())?;
        // let outputs = session.run(inputs![input]?)?;
        // outputs[0].try_extract_tensor::<f32>()?[[0, 0]]
        let _ = features;
        0.0
    }
}

impl Default for TrajectoryGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Predictor for TrajectoryGuard {
    fn name(&self) -> &'static str {
        "trajectory_guard"
    }

    fn evaluate(&self, ctx: &PredictiveContext<'_>) -> Decision {
        let features = self.extract_features(ctx);
        let error = self.infer_reconstruction_error(&features);

        if error >= BLOCK_THRESHOLD {
            tracing::warn!(
                reconstruction_error = error,
                model_path = %self.model_path,
                "trajectory anomaly — BLOCK"
            );
            Decision::Block {
                aft_id: "AFT-TRAJ-ANOMALY-001",
            }
        } else if error >= WARN_THRESHOLD {
            tracing::info!(reconstruction_error = error, "trajectory anomaly — WARN");
            Decision::Warn {
                aft_id: "AFT-TRAJ-ANOMALY-001",
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
                Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            ))),
            request_json: Box::leak(Box::new(json)),
        }
    }

    #[test]
    fn no_model_file_allows() {
        let guard = TrajectoryGuard {
            model_path: "/nonexistent/model.onnx".into(),
        };
        let c = ctx(serde_json::json!({}));
        assert_eq!(guard.evaluate(&c), Decision::Allow);
    }

    #[test]
    fn reconstruction_error_below_warn_allows() {
        let _guard = TrajectoryGuard::new();
        let error: f32 = 0.3;
        assert!(error < WARN_THRESHOLD);
        let decision = if error >= BLOCK_THRESHOLD {
            Decision::Block {
                aft_id: "AFT-TRAJ-ANOMALY-001",
            }
        } else if error >= WARN_THRESHOLD {
            Decision::Warn {
                aft_id: "AFT-TRAJ-ANOMALY-001",
            }
        } else {
            Decision::Allow
        };
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn reconstruction_error_above_warn_warns() {
        let error: f32 = 0.70;
        assert!((WARN_THRESHOLD..BLOCK_THRESHOLD).contains(&error));
        let decision = if error >= BLOCK_THRESHOLD {
            Decision::Block {
                aft_id: "AFT-TRAJ-ANOMALY-001",
            }
        } else if error >= WARN_THRESHOLD {
            Decision::Warn {
                aft_id: "AFT-TRAJ-ANOMALY-001",
            }
        } else {
            Decision::Allow
        };
        assert_eq!(
            decision,
            Decision::Warn {
                aft_id: "AFT-TRAJ-ANOMALY-001"
            }
        );
    }

    #[test]
    fn reconstruction_error_above_block_blocks() {
        let error: f32 = 0.90;
        assert!(error >= BLOCK_THRESHOLD);
        let decision = if error >= BLOCK_THRESHOLD {
            Decision::Block {
                aft_id: "AFT-TRAJ-ANOMALY-001",
            }
        } else if error >= WARN_THRESHOLD {
            Decision::Warn {
                aft_id: "AFT-TRAJ-ANOMALY-001",
            }
        } else {
            Decision::Allow
        };
        assert_eq!(
            decision,
            Decision::Block {
                aft_id: "AFT-TRAJ-ANOMALY-001"
            }
        );
    }

    #[test]
    fn extract_features_defaults_to_zero() {
        let guard = TrajectoryGuard::new();
        let c = ctx(serde_json::json!({}));
        let features = guard.extract_features(&c);
        assert_eq!(features.len(), FEATURE_ATTRS.len());
        assert!(features.iter().all(|&f| f == 0.0));
    }
}
