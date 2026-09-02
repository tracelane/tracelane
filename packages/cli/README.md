<!-- tracelane:classification: PUBLIC -->
# `tlane` — Tracelane CLI

[![npm](https://img.shields.io/npm/v/tlane?style=flat-square)](https://www.npmjs.com/package/@tracelanedev/cli)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](../../LICENSE)

Developer toolbox for Tracelane, the flight recorder for AI agents. A single binary covering trace inspection, audit verification, prompt promotion, agent replay, one-line migrations, and CI eval gates.

## Installation

```bash
npm install -g @tracelanedev/cli
# or
pnpm add -g @tracelanedev/cli
# or without installing (latest)
npx @tracelanedev/cli --version
```

## Quick start

```bash
# 1. Authenticate
export TRACELANE_TOKEN=tlane_YOUR_API_KEY
export TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev

# 2. Verify your first audit ledger. --tenant-pubkey is the trust root —
#    without it only the hash chain runs and the CLI exits non-zero.
tlane verify ./audit.ndjson --tenant-pubkey <base64>

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
tlane verify ./audit.ndjson --tenant-pubkey <base64>          # the real invocation
tlane verify ./audit.ndjson --tenant-pubkey <base64> --json   # machine-readable report
```

**`--tenant-pubkey` is what makes the run mean something.** Without it the verifier checks the hash chain only: signature and Rekor-anchor verification never run, so a forged anchor would not be caught. The CLI therefore exits **non-zero with `INCOMPLETE`** whenever a ledger contains anchor records and no trusted key was supplied. Get the key out-of-band from Settings → Audit signing key, or `GET /v1/audit/pubkey` — not from the export itself.

**Exit codes:** `0` = PASS, `1` = verification failure **or INCOMPLETE**, `2` = I/O error
or missing file.

```
tlane verify: PASS
  ledger:                ./audit.ndjson
  rows_seen:             14400
  hash_chain_valid:      true
  signatures_valid:      true
  rekor_anchors_seen:    24
  rekor_anchors_resolved:24
  anchors_included:      24 (Sigstore Rekor v2 · log2025-1.rekor.sigstore.dev)
```

Run it without the key and you get this instead — by design:

```
tlane verify: INCOMPLETE
  hash_chain_valid:      true
  signatures_valid:      NOT CHECKED — no --tenant-pubkey
```

### `tlane prompt`

Prompt promotion and rollback with a tamper-evident promotion record. Requires `TRACELANE_TOKEN` and `TRACELANE_GATEWAY_URL`.

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

Generate a documentation pack — static markdown templates describing how Tracelane logs, which models it routes to, and how it handles data, plus a `manifest.json`, emitted as a ZIP.

**It reads no ledger and makes no network calls, so it contains none of your data.** For your actual ledger, export it from `/v1/audit/export` and run `tlane verify`.

```bash
tlane export --pack eu-ai-act-art12     # chain design, model registry, data-processing, guardrails
tlane export --pack dpdp-phase-2        # storage region, processor/controller split, rights procedure
tlane export --pack eu-ai-act-art12 --output-dir ./docs-pack
```

### `tlane migrate`

One-command migration from Helicone or LiteLLM.

```bash
# Helicone → Tracelane. Scans the project root, prints a diff,
# writes nothing without --apply.
tlane migrate helicone
tlane migrate helicone --apply
tlane migrate helicone --dir ./services/api --apply

# LiteLLM config → Tracelane gateway config. --config is a flag; a path
# passed positionally is ignored in favour of the default litellm_config.yaml.
tlane import-litellm --config ./litellm_config.yaml
tlane import-litellm --config ./litellm_config.yaml --output tracelane.yaml --dry-run
```

`migrate helicone` rewrites the env and source files it found, in place.
`import-litellm` emits a Tracelane-compatible `tracelane.yaml`, preserving
provider routing, model aliases, and rate-limit metadata.

### `tlane replay`

Read-only time-travel viewer — renders a recorded trace's spans step-by-step
It does not re-execute the trace; cross-model re-execution is on the roadmap.

```bash
tlane replay <trace-id>
tlane replay <trace-id> --format json
tlane replay <trace-id> --endpoint https://gateway.tracelane.dev
```

### `tlane eval` — the CI gate

`eval run` runs a frozen dataset (or an inline case list) against a prompt
version through the gateway and **exits non-zero when the mean score falls below
the `--threshold` floor**, so a change that drops below your bar cannot merge. `eval list` shows recent eval runs
in your workspace. Neither needs a checkout.

```bash
tlane eval run --prompt support-triage \
               --dataset golden-cases \
               --suite-file .tracelane/triage.eval.json \
               --threshold 0.8
tlane eval list --limit 20
```

The prompt version is resolved from `--env` (default `staging`), so no UUID has
to live in your workflow file; `--version-id` pins one. The suite file holds the
assertions — `{"assertions":[{"kind":"contains","value":"refund"}]}` — and must
declare at least one. A run that asserts nothing scores every case as passed, so
the gate would report 100% on the day the prompt breaks; the CLI refuses it with
exit 2 before spending a provider call.

**The comparison, stated:** higher is better and `--threshold` is a **floor** —
`--threshold 0.8` means "fail if the mean score is below 0.8". A **tie passes**
(`score == threshold` exits 0), because a gate that fails on exactly the number
you set is a gate nobody can configure. `--threshold` is a fraction in `[0,1]`,
so a bare `80` is rejected rather than read as 8000%.

**It thresholds the mean SCORE, not the pass rate.** For `contains`,
`exact_match` and `json_schema` a case scores exactly `1.0` or `0.0`, so the mean
*is* the pass rate. For an LLM judge the score is continuous, and there the two
differ: a judge scoring 0.68 against a 0.70 rule and one scoring 0.02 are the
same "failed" and very different results.

**Errored cases are excluded from the mean**, not scored as zero. One provider
`429` in a twenty-case run is not a quality problem. They are bounded separately by
`--max-error-rate` (default `0.10`); above it, and for a run where every case
errored, the verdict is **could not evaluate** (exit `3`) — never a pass and
and never a statement about your prompt at all.

**This gate asserts a FLOOR on a single run — it does not detect regressions.**
There is no baseline, no history and no comparison: the same shape as a coverage
threshold, which nobody considers broken for lacking a previous run. A run
scoring 0.9 today and 0.85 tomorrow clears a 0.8 floor both times, and calling
the second "no regression" would be a claim nothing checked. Comparing a run
against an earlier one is a real gap and is filed, not built — what counts as
the baseline is a design decision, not a flag.

The three-line GitHub Action wrapper is at
[`.github/actions/eval-gate`](https://github.com/tracelane/tracelane/tree/main/.github/actions/eval-gate).

**Changed in `0.3.0`:** `eval run` used to shell out to the repo's vitest runner.
To run Tracelane's own conformance suite from a checkout, use
`pnpm eval:run --suite=all`; the old `--suite` flag exits 2 with that pointer
rather than failing as an unknown option.

### `tlane init`

Scaffold Tracelane into the project in the working directory. Four steps, each
one skippable:

| Step | What lands | Skip with |
|---|---|---|
| Config | `tracelane.config.json` — `endpoint`, `serviceName`, `sampleRate` | — |
| Env | `TRACELANE_API_KEY` and `TRACELANE_GATEWAY_URL` merged into `.env`, and `.env` added to an existing `.gitignore` | `--no-env` |
| Instrumentation | `tracelane.ts` / `tracelane.mjs` / `tracelane_init.py` wiring the SDK to the frameworks found in your manifests | `--no-instrument` |
| Install | `@tracelanedev/sdk` or `tracelane`, installed with your own package manager | `--no-install` |

**Framework detection** reads `package.json` for Node and
`pyproject.toml` / `requirements.txt` / `Pipfile` for Python, and matches them
against the SDK's adapters. A polyglot repo gets both bootstraps.

**How far the bootstrap gets on its own, honestly.** On Python it emits
`init(..., auto_instrument=True)`, which really does wrap installed `openai`,
`anthropic`, `litellm` and `claude_code` with no further edit. Everything else —
including every TypeScript adapter — wraps an object only you can construct, so
the bootstrap imports the right `instrument*` function and emits the exact
one-line call next to it. The TypeScript SDK has no zero-config patching:
`autoInstrument()` throws by design and lands in v1.1.

**What it will not do.** `.env` is only ever appended to — an existing
`TRACELANE_API_KEY` is never rewritten, `--force` included. An existing config or
bootstrap is kept unless you pass `--force`. A failed install exits non-zero and
prints the command to re-run; the scaffolded files stay.

**Package manager** comes from the lockfile: `pnpm-lock.yaml` → `pnpm add`,
`yarn.lock` → `yarn add`, `bun.lock*` → `bun add`, otherwise `npm install`; and
`uv.lock` → `uv add`, `poetry.lock` or `[tool.poetry]` → `poetry add`, `Pipfile`
→ `pipenv install`, otherwise `python3 -m pip install`.

`--endpoint` is the OTLP endpoint spans are exported to. On Tracelane Cloud that
is `https://gateway.tracelane.dev`, with a `tlane_…` key carrying the `ingest`
scope. Self-hosting, it is the ingest receiver you run. The default is
`http://localhost:4318`, so **on Cloud, pass `--endpoint` explicitly**.

```bash
tlane init --endpoint https://gateway.tracelane.dev          # Tracelane Cloud
tlane init --endpoint http://otel-collector.internal:4318
tlane init --service-name checkout-agent --sample-rate 0.25 --force
tlane init --no-install --no-env          # config + bootstrap only
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
| `TRACELANE_API_KEY` | API key used by `tlane trace`, by the bootstrap `tlane init` generates, and as a `TRACELANE_TOKEN` fallback for `tlane replay` |
| `TRACELANE_GATEWAY_URL` | Gateway base URL (default: `http://localhost:8080`) |


## Stack

TypeScript 5.5 + Commander.js. Built with `tsup`, distributed via npm. Runtime deps: `@tracelanedev/audit-verifier`, `chalk`, `commander`, `fflate`, `ora`, `yaml`.

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
