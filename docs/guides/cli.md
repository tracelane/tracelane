<!-- tracelane:classification: PUBLIC -->
# `tlane` — Tracelane CLI

The `tlane` CLI is the operator-side companion to the Tracelane gateway. It
covers project bootstrap, trace inspection, eval orchestration, prompt
versioning, audit-log verification, documentation packs, and migration
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

Writes a `tracelane.config.json` (endpoint, `serviceName`, `sampleRate`) to the
working directory, then prints the SDK install + wire-up steps. It writes that
one file and nothing else — it does not install a package, create `.env`, or
edit your source. Without `--force` it refuses to overwrite an existing config.

`--endpoint` is the OTLP endpoint spans are exported to. On Tracelane Cloud that
is `https://gateway.tracelane.dev`, with a `tlane_…` key carrying the `ingest`
scope. Self-hosting, it is the ingest receiver you run. The default is
`http://localhost:4318`, so **on Cloud, pass `--endpoint` explicitly**.

```bash
tlane init --endpoint https://gateway.tracelane.dev         # Tracelane Cloud
tlane init --endpoint http://otel-collector.internal:4318   # self-run receiver
tlane init --service-name checkout-agent --sample-rate 0.25
tlane init --force                                          # overwrite existing
```

Output: the config path plus a printed next-steps checklist that mirrors the
[60-second quickstart](./quickstart.md).

### `tlane trace <traceId>`

Fetch a trace by its OTLP `trace_id` and render it. The CLI calls the Tracelane
API directly — `--endpoint` (default `https://app.tracelane.dev`) with
`--api-key`, falling back to `TRACELANE_API_KEY` — so the same tenant-scoped
auth and filtering rules as the dashboard apply.

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

Drive the eval suite from the command line. `eval run` shells out to the repo's
vitest runner and is what CI calls; `eval list` reads the local eval index and is
for humans.

```bash
tlane eval run                                  # all suites
tlane eval run --suite gc                       # gateway-correctness only
tlane eval run --suite pp                       # pain-points only
tlane eval run --suite ft --dry-run             # print the command, don't run it
tlane eval list
```

Suite ids: `all`, `ft` (fault-tolerance), `gc` (gateway-correctness),
`is` (ingest-schema), `pp` (pain-points), `pir` (pii-redaction),
`pi` (prompt-injection). An unrecognised id exits 2 rather than falling through
to a full run — a wrong suite name in a deploy gate must fail loudly. The merge
gate is `--suite all`.

`eval run` takes only `--suite` and `--dry-run`; `eval list` takes no flags. Both
need a checkout of the Tracelane repository, since the eval suites do not ship in
the npm package.

### `tlane prompt list | show | promote | rollback | diff`

Front-end for the [B1 Prompt Promotion](../../decisions/ADR-009-b1-prompt-promotion.md)
endpoints. Tenants pin a prompt version per environment, promote with a
contract test, and roll back instantly.

Every subcommand takes the prompt **name** as a positional argument — there is no
"list everything in the tenant" form. All of them also accept `--gateway <url>`
and `--token <bearer>`, defaulting to `$TRACELANE_GATEWAY_URL` and
`$TRACELANE_TOKEN`.

```bash
tlane prompt list pricing-v3 --limit 100           # promote + rollback history
tlane prompt show pricing-v3                       # resolved version per env
tlane prompt show pricing-v3 --env production
tlane prompt promote pricing-v3 --from staging --to production --version-id <uuid>
tlane prompt promote pricing-v3 --to production --version-id <uuid> --eval-run <uuid>
tlane prompt rollback pricing-v3 --env production --version-id <uuid> --reason "sigma drift 3.2σ"
tlane prompt diff pricing-v3 --from-env staging --to-env production
```

`promote` and `rollback` exit 2 without `--version-id` — neither has a
"previous version" default. The eval gate is `--eval-run <uuid>`, an eval-run
id rather than an eval name. `diff` fetches the resolved version from two
**environments** (`--from-env` / `--to-env`, both required), not two version
numbers.

Server endpoints: `/v1/prompts`, `/v1/prompts/:id`, `/v1/prompts/:id/promote`,
`/v1/prompts/:id/rollback`. See [api-reference.md](./api-reference.md).

### `tlane verify <ledger.ndjson>`

Verify a tamper-evident audit ledger without the gateway. Re-runs the per-tenant
SHA-256 hash chain always, and — only when you supply `--tenant-pubkey` — the
Ed25519 signatures and any resolved Sigstore Rekor v2 inclusion proof.
Divergences print with their `seq` (first 10).

```bash
tlane verify audit-2026-04.ndjson --tenant-pubkey <base64>
tlane verify audit-2026-04.ndjson --tenant-pubkey <base64> --json   # machine-readable
```

**`--tenant-pubkey` is what makes the run mean something.** Without it the verifier checks the hash chain only: signature and Rekor-anchor verification never run, so a forged anchor would not be caught. The CLI therefore exits **non-zero with `INCOMPLETE`** whenever a ledger contains anchor records and no trusted key was supplied. Get the key out-of-band from Settings → Audit signing key, or `GET /v1/audit/pubkey` — not from the export itself.

The Rust, Python, and TypeScript verifiers are **identical by construction**
on the current `v2.1` format (ADR-050): each hashes the exported payload's
verbatim canonical string byte-for-byte, so there is no re-derivation to
diverge on. The JS one is what `tlane verify` runs; CI tests all three against
the same conformance vectors (`evals/audit-ledger/`), including the JS-unsafe
number class that motivated the format. (Legacy `v2` packs — payload as a
nested object — are re-canonicalized on read and can differ across languages
on those numbers; re-export under `v2.1` for robust cross-language verification.)

### `tlane export --pack <name>`

Generate a **documentation pack**: a set of static markdown templates describing
how Tracelane logs, which models it routes to, and how it handles data, plus a
machine-readable `manifest.json`, emitted as a ZIP.

**It reads no ledger and makes no network calls, so it contains none of your
data.** It is written documentation about the system, not evidence drawn from
your workspace. To produce something about *your* ledger, export it from
`/v1/audit/export` and run `tlane verify`.

`--pack` is required and is a flag, not a positional argument. `--output-dir`
is the staging directory for the pack files (default `./compliance-pack`); the
ZIP lands in the working directory unless you pass `--no-zip`, which keeps the
directory and skips the archive. There is no `--output` flag.

```bash
tlane export --pack eu-ai-act-art12 --output-dir ./docs-pack
tlane export --pack dpdp-phase-2 --output-dir ./docs-pack
tlane export --pack dpdp-phase-2 --no-zip
```

| Pack (the value for `--pack`) | What the templates describe |
|---|---|
| `eu-ai-act-art12` | The hash chain and anchoring design, the model registry, the data-processing record, and the guardrail catalogue |
| `dpdp-phase-2` | Storage-region configuration, the processor/controller split, and the rights-request procedure |

### `tlane migrate helicone`

Rewrite a project's Helicone wiring in place. Scans the project root for env
files and for source files carrying Helicone references, prints a diff of every
proposed change, and stops there by default. `--apply` writes the rewritten
files after an interactive `[y/N]` confirm. It rewrites the files it found; it
does not synthesise a `tracelane.yaml`.

```bash
tlane migrate helicone                              # dry-run diff, writes nothing
tlane migrate helicone --apply                      # apply after confirmation
tlane migrate helicone --dir ./services/api --apply # scan a different root
tlane migrate helicone --endpoint https://gateway.acme.internal --apply
```

The flags are `--apply`, `--dir <path>` (default: cwd) and `--endpoint <url>`
(default `https://gateway.tracelane.dev`, used in the printed next-steps).

Mapping is documented in [migrations/from-helicone.md](./migrations/from-helicone.md).

### `tlane import-litellm --config <path>`

Translate a LiteLLM `model_list` to Tracelane gateway routing. Preserves the
provider, model alias, and rate-limit metadata. Caller-side code that calls
`litellm.completion(...)` keeps working through Tracelane's
OpenAI-compatible `/v1/chat/completions` endpoint — no
SDK swap needed.

The config path is a flag, not a positional argument. A path passed positionally
is ignored and the default `litellm_config.yaml` in the working directory is read
instead — so always pass `--config` explicitly.

```bash
tlane import-litellm --config ./litellm_config.yaml --output tracelane.yaml
tlane import-litellm --config ./litellm_config.yaml --dry-run
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
| 1 | Logical failure — verification failed or `INCOMPLETE`, unknown pack, server error |
| 2 | Bad invocation or I/O — missing file, missing required flag, unknown eval suite |

Those are the only codes the CLI emits; there is no separate divergence or
incomplete-pack code. `tlane export` reports per-item `placeholder` / `missing`
status in the printed manifest and still exits 0. `tlane eval run` is the one
exception to the table: it passes through the underlying test runner's exit code.
CI should gate on non-zero.

## Related

- [Quickstart](./quickstart.md) — your first trace in 60 seconds
- [API reference](./api-reference.md) — what the CLI calls
- [Onboarding](./onboarding.md) — operator self-host checklist
- [`decisions/ADR-009-b1-prompt-promotion.md`](../../decisions/ADR-009-b1-prompt-promotion.md)
- [`decisions/ADR-011-path-to-live.md`](../../decisions/ADR-011-path-to-live.md)
