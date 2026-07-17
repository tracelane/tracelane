# ml

Tracelane's ML pipeline for the predictive guardrail layer.

## Components

### trajectory_guard/

Siamese recurrent autoencoder (arXiv 2601.00516) for trajectory-level
anomaly detection. Trained on 50K trace pairs (normal vs. failure modes).
Exported to ONNX for inference in the Rust gateway (<30ms p99, Week 8).

**AFT:** AFT-TRAJ-ANOMALY-001

### slm_judge/

Distilled 1B encoder judge. Distilled from Llama-Guard 8B + NemoGuard 8B.
Evaluates: flow adherence, tool-selection sanity, hallucination grounding.
Target: <50ms p99, ≥1K req/sec on single L4 GPU. Deployed on Modal/RunPod.

**Eval:** PP-PR10

### eval_corpus/

Attack corpus and benchmark datasets. 5K patterns from:
- Invariant Labs MCP attacks
- EchoLeak prompt injection patterns
- Promptfoo red-team library
- TRAIL anomalies

Versioned in DVC. Updated quarterly.

## Training pipeline (Week 8)

```bash
# Trajectory Guard
cd ml/trajectory_guard
python train.py --dataset eval_corpus/trace_pairs.dvc
python export_onnx.py --output ../../crates/gateway/models/trajectory_guard.onnx

# SLM Judge
cd ml/slm_judge
python distill.py --teacher llama-guard-8b,nemoguard-8b --output slm_judge_1b.pt
python export_onnx.py --output ../../crates/gateway/models/slm_judge.onnx
```

## Inference (in Rust gateway)

ONNX Runtime crate. Models loaded at gateway startup, kept in memory.
Inference runs inline in the predictive layer on every request.
