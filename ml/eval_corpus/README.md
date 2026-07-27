# eval_corpus — Attack Corpus and Benchmark Datasets

Attack patterns and trace pairs for training and evaluating the predictive layer.

## Contents

| File | Size | Source | Description |
|---|---|---|---|
| `trace_pairs.ndjson` | ~50K pairs | Tracelane synthetic | Trajectory Guard training pairs (normal vs. failure) |
| `judge_labels.ndjson` | ~20K samples | LlamaGuard + NemoGuard labels | SLM Judge distillation dataset |
| `mcp_attacks.ndjson` | 1K patterns | Invariant Labs | MCP rug-pull and arg-drift attack patterns |
| `prompt_injection.ndjson` | 2K patterns | EchoLeak CVEs | Prompt injection cascade patterns |
| `captcha_urls.txt` | 500 URLs | Manual curation | CAPTCHA service URL patterns |
| `lethal_trifecta.ndjson` | 1K samples | Synthetic | Lethal trifecta taint combinations |

## DVC tracking

All large files are tracked with DVC. Run `dvc pull` to download:

```bash
dvc pull eval_corpus/trace_pairs.dvc
dvc pull eval_corpus/judge_labels.dvc
```

Remote: Cloudflare R2 bucket `tracelane-ml-artifacts` (configured in `.dvc/config`).

## Dataset generation

### trace_pairs (for Trajectory Guard)
```bash
cd ml/trajectory_guard
python train.py --synthetic  # smoke test with 4K synthetic pairs
# Full dataset: use real traces from Tracelane dogfooding instance
```

### judge_labels (for SLM Judge)
```bash
cd ml/slm_judge
# Label with teachers (requires GPU + HuggingFace access):
python label_with_teachers.py \
    --teacher-safety meta-llama/LlamaGuard-7b \
    --teacher-grounding nvidia/nemotron-mini-4b-instruct \
    --corpus-path mcp_attacks.ndjson \
    --output judge_labels.ndjson
```

## Update schedule

Corpus is updated quarterly with new attack patterns from:
- Invariant Labs MCP attack research
- EchoLeak CVE disclosures
- Promptfoo red-team library
- TRAIL anomaly benchmark
- Tracelane customer incident reports (anonymised)
