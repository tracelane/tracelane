# `tlane` — Tracelane CLI

[![npm](https://img.shields.io/npm/v/tlane?style=flat-square)](https://www.npmjs.com/package/tlane)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](../../LICENSE)

Developer toolbox for the Tracelane predictive reliability platform. A single binary covering trace inspection, audit verification, prompt promotion, agent replay, one-line migrations, and CI eval gates.

## Installation

```bash
npm install -g tlane
# or
pnpm add -g tlane
# or without installing (latest)
npx tlane --version
```

## Quick start

```bash
# 1. Authenticate
export TRACELANE_TOKEN=tlane_YOUR_API_KEY
export TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev

# 2. Verify your first audit ledger
tlane verify ./audit.ndjson

# 3. Show active prompt versions
tlane prompt show my-agent-prompt

# 4. Promote staging → production (eval-gated)
tlane prompt promote my-agent-prompt \
  --from staging --to production \
  --version-id abc12345-...
```

## Commands

### `tlane verify`

Verify a tamper-evident audit ledger against the Ed25519/SHA-256 hash chain and Sigstore Rekor anchors.

```bash
tlane verify ./audit.ndjson
tlane verify ./audit.ndjson --offline     # skip Rekor network calls
tlane verify ./audit.ndjson --json        # machine-readable JSON report
```

**Exit codes:** `0` = PASS, `1` = verification failure, `2` = I/O error.

```
tlane verify: PASS
  ledger:                ./audit.ndjson
  rows_seen:             14400
  hash_chain_valid:      true
  signatures_valid:      true
  rekor_anchors_seen:    24
  rekor_anchors_resolved:24
```

### `tlane prompt`

B1 Prompt Promotion + Eval Gates + Auto-Rollback. Requires `TRACELANE_TOKEN` and `TRACELANE_GATEWAY_URL`.

```bash
# Show active version per environment
tlane prompt show my-prompt
tlane prompt show my-prompt --env production

# Promote staging → production
tlane prompt promote my-prompt \
  --from staging --to production \
  --version-id <uuid> \
  [--eval-run <uuid>]   # gate on eval run

# Force rollback
tlane prompt rollback my-prompt \
  --env production \
  --version-id <uuid> \
  --reason "sigma drift 3.2σ"

# Diff two environments
tlane prompt diff my-prompt --from-env staging --to-env production

# List promotion + rollback history
tlane prompt list my-prompt [--limit 100]
```

**Available on:** Team $249+ for full promote/rollback workflow. Builder $59 can list and show (read-only).

### `tlane export`

Export audit evidence packs for regulatory compliance.

```bash
tlane export --pack eu-ai-act-art12     # EU AI Act Article 12 evidence pack
tlane export --pack dpdp-phase-2        # India DPDP Phase 2 evidence pack
tlane export --since 2025-01-01 --format ndjson
```

### `tlane migrate`

One-line migration from Helicone or LiteLLM.

```bash
# Helicone → Tracelane (PP-G4)
tlane migrate --from helicone --url https://oai.helicone.ai

# LiteLLM config → Tracelane gateway config
tlane import-litellm ./litellm_config.yaml
```

Outputs a Tracelane-compatible `tracelane.yaml` config. Preserves all provider routing, model mappings, and rate-limit rules.

### `tlane replay`

Read-only time-travel viewer — renders a recorded trace's spans step-by-step
(PP-O8). It does not re-execute the trace; cross-model re-execution is on the roadmap.

```bash
tlane replay <trace-id>
tlane replay <trace-id> --format json
tlane replay <trace-id> --endpoint https://gateway.tracelane.dev
```

### `tlane eval`

Run the eval suite or list eval status.

```bash
tlane eval run                             # run all evals
tlane eval run --suite gateway             # run gateway-only suite
tlane eval run --suite predictive --gate   # fail CI on regression
tlane eval list                            # list all pain-point evals + status
```

Use `--gate` in CI to fail the job on any regression — this is the B1 merge gate.

### `tlane init`

Scaffold a new project with Tracelane SDK + `TRACELANE_API_KEY` env setup.

```bash
tlane init
tlane init --endpoint https://gateway.tracelane.dev
```

### `tlane trace`

Fetch and display a specific trace.

```bash
tlane trace <trace-id>
tlane trace <trace-id> --format json
tlane trace <trace-id> --format timeline
```

## Environment variables

| Variable | Description |
|---|---|
| `TRACELANE_TOKEN` | API key (`tlane_...`) or Bearer JWT |
| `TRACELANE_GATEWAY_URL` | Gateway base URL (default: `http://localhost:8080`) |

## Pain points addressed

| ID | Description |
|---|---|
| PP-G1 | Developer onboarding — `tlane init` scaffolds in < 60 s |
| PP-G4 | One-line Helicone migration — `tlane migrate --from helicone` |
| PP-O8 | Agent replay across model versions — `tlane replay` |
| PP-O11 | CI eval gate — `tlane eval run --gate` in GitHub Actions |
| PP-PR6 | Audit ledger verification — `tlane verify` (exit code 0/1/2) |

## Stack

TypeScript 5.5 + Commander.js. Built with `tsup`, distributed via npm. No runtime deps beyond `commander`.

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
