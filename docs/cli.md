# `tlane` — Tracelane CLI

The `tlane` CLI is the operator-side companion to the Tracelane gateway. It
covers project bootstrap, trace inspection, eval orchestration, prompt
versioning, audit-log verification, compliance evidence packs, and migration
from competing tools.

Install:

```bash
npm install -g @tracelanedev/cli
# or run without install
npx tlane <command>
```

All commands respect these env vars:

| Var | Purpose | Default |
|---|---|---|
| `TRACELANE_API_KEY` | Tenant API key (`tlane_<base62>`) | required for live commands |
| `TRACELANE_GATEWAY_URL` | Gateway base URL | `https://gateway.tracelane.dev` |
| `TRACELANE_TRACE_CONTENT` | Capture full prompt/response payload in spans | `false` |

`tlane --help` lists everything; this page is the prose tour.

## Commands

### `tlane init`

Initialise Tracelane in the current project. Creates `.env` with
`TRACELANE_*` placeholders, installs the right SDK
(`@tracelanedev/sdk` or `tracelane` for Python), and instruments any
detected agent framework (LangChain, LlamaIndex, CrewAI, OpenAI Agents SDK).

```bash
tlane init
tlane init --endpoint https://gateway.acme.internal   # self-host
```

Output: a printable "first-trace checklist" that mirrors the
[60-second quickstart](./quickstart.md).

### `tlane trace <traceId>`

Fetch a trace by its OTLP `trace_id` and render it. The MCP server is the
canonical read path; the CLI proxies through `npx @tracelanedev/mcp` so the same
auth + filtering rules apply.

```bash
tlane trace 9f2c8a1b...                         # default: table
tlane trace 9f2c8a1b... --format json
tlane trace 9f2c8a1b... --format timeline       # ASCII waterfall
```

`--format timeline` is what most operators want for the on-call workflow:

```
[ 0ms]  POST /v1/messages     anthropic     ████████████░░░░     142ms
[12ms]  rerank                cohere        ░░░██░░░░░░░░░░░      18ms
[15ms]  tool: search          tavily        ░░░░░██████░░░░░      54ms
[42ms]  POST /v1/messages     anthropic     ░░░░░░░░░░██░░░       97ms
                                            └─ predictive: ARG_DRIFT (0.62)
```

### `tlane eval run` / `tlane eval list`

Drive the Python eval orchestrator from the command line. `eval run` is what
CI calls; `eval list` is for humans.

```bash
tlane eval run                                  # all suites
tlane eval run --suite gateway
tlane eval run --suite predictive --tag PR1
tlane eval list
tlane eval list --status red                    # only failing
```

Suites: `all`, `gateway`, `ingest`, `predictive`, `pain-points`,
`fault-tolerance`. The merge gate is `--suite all`.

### `tlane prompt list | show | promote | rollback | diff`

Front-end for the [B1 Prompt Promotion](../decisions/ADR-009-b1-prompt-promotion.md)
endpoints. Tenants pin a prompt version per environment, promote with a
contract test, and roll back instantly.

```bash
tlane prompt list                                  # all prompts in this tenant
tlane prompt show pricing-v3                       # version + env pinning
tlane prompt promote pricing-v3 --to staging
tlane prompt promote pricing-v3 --to production --eval-passed PP-PR1
tlane prompt rollback pricing-v3 --env production  # to previous pinned ver
tlane prompt diff pricing-v3 --from v7 --to v8     # git-style visual diff
```

Server endpoints: `/v1/prompts`, `/v1/prompts/:id`, `/v1/prompts/:id/promote`,
`/v1/prompts/:id/rollback`. See [api-reference.md](./api-reference.md).

### `tlane verify <ledger.ndjson>`

Verify a tamper-evident audit ledger end-to-end without the gateway. Re-runs
the SHA-256 hash chain, checks every Sigstore Rekor inclusion proof, and
prints the first divergence (if any) with the offending line number.

```bash
tlane verify audit-2026-04.ndjson
tlane verify audit-2026-04.ndjson --rekor-offline   # skip Rekor lookups
tlane verify audit-2026-04.ndjson --strict          # any warning fails
```

The Rust, Python, and TypeScript verifiers are **identical by construction**
on the current `v2.1` format (ADR-050): each hashes the exported payload's
verbatim canonical string byte-for-byte, so there is no re-derivation to
diverge on. The JS one is what `tlane verify` runs; CI tests all three against
the same conformance vectors (`evals/audit-ledger/`), including the JS-unsafe
number class that motivated the format. (Legacy `v2` packs — payload as a
nested object — are re-canonicalized on read and can differ across languages
on those numbers; re-export under `v2.1` for robust cross-language verification.)

### `tlane export <pack> --output <dir>`

Generate compliance evidence packs. Pulls from the audit chain (Rekor-anchored)
and the span store; emits a ZIP with evidence files plus a machine-readable
`manifest.json`.

```bash
tlane export eu-ai-act-art12 --output ./evidence
tlane export dpdp-phase-2 --output ./evidence
```

| Pack | Coverage |
|---|---|
| `eu-ai-act-art12` | Transparency + audit logging (Article 12) |
| `dpdp-phase-2` | India DPDP — data localisation + consent records |

### `tlane migrate helicone`

Translate a Helicone configuration into a Tracelane configuration. Reads the
caller's `.env` for `HELICONE_*` vars and emits `.env.tracelane` with the
renamed equivalents. With `--with-config --src <dir>`, also greps for
`Helicone-Property-*` headers and synthesises a `tracelane.yaml` with
matching tenant/route metadata.

```bash
tlane migrate helicone                           # dry-run scan
tlane migrate helicone --apply                   # write .env.tracelane
tlane migrate helicone --apply --with-config --src src/
```

Mapping is documented in [migrations/from-helicone.md](./migrations/from-helicone.md).

### `tlane import-litellm <litellm_config.yaml>`

Translate a LiteLLM `model_list` to Tracelane gateway routing. Preserves the
provider, model alias, and rate-limit metadata. Caller-side code that calls
`litellm.completion(...)` keeps working through Tracelane's
OpenAI-compatible `/v1/messages` and `/v1/chat/completions` endpoints — no
SDK swap needed.

```bash
tlane import-litellm litellm_config.yaml --output tracelane.yaml
tlane import-litellm litellm_config.yaml --dry-run
```

### `tlane replay <traceId>`

Read-only time-travel viewer. Fetches a recorded trace's spans from the gateway
(`GET /v1/traces/{id}/spans`) and renders them step-by-step in the terminal —
exact inputs, tool calls, durations, and the captured LLM output for each span.
It does **not** re-issue the request to a provider.

```bash
tlane replay 9f2c8a1b...                          # render the recorded trace
tlane replay 9f2c8a1b... --format json            # pipe to other tools
tlane replay 9f2c8a1b... --endpoint https://gateway.tracelane.dev
```

Useful for: stepping through a past run, inspecting tool inputs/outputs, and
sharing a reproducible trace. Re-executing a captured trace against a different
model or provider (cross-model shadow-fork replay) is on the roadmap.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | User-facing error (bad args, missing file, server 4xx) |
| 2 | Operator error (gateway 5xx, network, auth) |
| 3 | Eval / verifier divergence — non-empty failure list |
| 4 | Compliance pack incomplete (some items `placeholder`/`missing`) |

CI should treat code 3 as a hard merge block; code 4 as a warning gate.

## Related

- [Quickstart](./quickstart.md) — your first trace in 60 seconds
- [API reference](./api-reference.md) — what the CLI calls
- [Onboarding](./onboarding.md) — operator self-host checklist
- [`decisions/ADR-009-b1-prompt-promotion.md`](../decisions/ADR-009-b1-prompt-promotion.md)
- [`decisions/ADR-011-path-to-live.md`](../decisions/ADR-011-path-to-live.md)
