# ml

Tracelane's ML pipeline for the predictive guardrail layer.

## Components

### trajectory_guard/

**STATUS: NOT TRAINED, NOT SHIPPED — this directory is a training pipeline, not a model.**
No `.onnx` weights are tracked in this repository and the gateway loads none.

*Design* (unbuilt): a Siamese recurrent autoencoder (arXiv 2601.00516) for
trajectory-level anomaly detection, to be trained on trace pairs (normal vs.
failure modes) and exported to ONNX for inference in the Rust gateway. The
corresponding gateway predictors are fail-open stubs today.

**AFT:** AFT-TRAJ-ANOMALY-001

### slm_judge/

**STATUS: NOT TRAINED, NOT DEPLOYED.** *Design* (unbuilt): a distilled 1B
encoder judge intended to evaluate flow adherence, tool-selection sanity and
hallucination grounding. Nothing is distilled, deployed, or serving today.

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
