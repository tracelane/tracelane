<!-- tracelane:classification: PUBLIC -->
# ml

Training and export code for Tracelane's machine-learning predictors.

**No trained model ships in this repository, and neither does any training data.**
The gateway's ML-based predictors are not enabled today; the rule-based guardrails are
what run inline. The code here is published so the pipeline can be read and reproduced,
not because a model built from it is in use.

| Directory | What it is | What you need to run it |
|---|---|---|
| `prompt_guard_export/` | Exports Meta's Llama Prompt Guard 2 22M to INT8 ONNX. `SHA256SUMS` holds a `PENDING` placeholder until an export is pinned. | A Hugging Face token with access to the model, and acceptance of the Llama Community License. |
| `prompt_guard/` | A small FastAPI sidecar that serves the exported ONNX model. | The file produced by `prompt_guard_export/`. |
| `trajectory_guard/` | A trajectory-anomaly model: dataset loader, model, training loop and ONNX export. | Your own labelled trace-pair dataset (NDJSON; format in `dataset.py`). |
| `slm_judge/` | Distillation and ONNX export for a small judge model. | Your own teacher-labelled dataset (NDJSON; format in `distill.py`). |

The labelled corpora the maintainers train on are not distributed and are held
privately. Nothing in this directory downloads them.
