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
# Helicone → Tracelane (PP-G4). Scans the project root, prints a diff,
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
(PP-O8). It does not re-execute the trace; cross-model re-execution is on the roadmap.

```bash
tlane replay <trace-id>
tlane replay <trace-id> --format json
tlane replay <trace-id> --endpoint https://gateway.tracelane.dev
```

### `tlane eval`

Run the eval suite or list eval status. Both need a checkout of the Tracelane
repository — the eval suites do not ship in the npm package.

```bash
tlane eval run                             # run all evals
tlane eval run --suite gc                  # gateway-correctness suite only
tlane eval run --suite gc                  # gateway-correctness suite only
tlane eval run --suite ft --dry-run        # print the command without running it
tlane eval list                            # list every conformance eval
```

Suite ids: `all`, `ft` (fault-tolerance), `gc` (gateway-correctness),
`is` (ingest-schema), `pir` (pii-redaction),
`pi` (prompt-injection). An unrecognised id exits 2 instead of silently running
everything.

`eval run` exits with the underlying test runner's status, so CI gates on
non-zero — that is the B1 merge gate. There is no `--gate` flag.

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

## Pain points addressed

| ID | Description |
|---|---|
| PP-G1 | Developer onboarding — `tlane init` scaffolds in < 60 s |
| PP-G4 | One-command Helicone migration — `tlane migrate helicone --apply` |
| PP-O8 | Agent replay of a recorded trace — `tlane replay` |
| PP-O11 | CI eval gate — `tlane eval run --suite all` in GitHub Actions |
| PP-PR6 | Audit ledger verification — `tlane verify` (exit code 0/1/2) |

## Stack

TypeScript 5.5 + Commander.js. Built with `tsup`, distributed via npm. Runtime deps: `@tracelanedev/audit-verifier`, `chalk`, `commander`, `fflate`, `ora`, `yaml`.

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
