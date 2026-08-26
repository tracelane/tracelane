<!-- tracelane:classification: PUBLIC -->
# Tracelane

**flight recorder for AI agents.**

[![CI](https://github.com/tracelane/tracelane/actions/workflows/ci.yml/badge.svg)](https://github.com/tracelane/tracelane/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OTel GenAI semconv](https://img.shields.io/badge/OTel-GenAI%20semconv-brightgreen)](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
[![Cosign verified](https://img.shields.io/badge/releases-cosign%20verified-blueviolet)](SECURITY.md#verifying-release-artifacts)

**[Get started free →](https://app.tracelane.dev/sign-in)** · [Docs](https://docs.tracelane.dev) · [Discussions](https://github.com/tracelane/tracelane/discussions)

---

## What it does

Tracelane sits between your AI agents and your LLM providers. You get:

- **BYOK proxy** — point agents at `https://gateway.tracelane.dev`, pass your own API key. 0% markup.
- **Full-fidelity traces** — every LLM call, tool invocation, agent step, and retry captured as OTel spans using the GenAI semantic conventions. Full capture is the default; there is no sampling you have to turn off. The one bound we do apply is a per-trace ceiling (10,000 spans / 64 MiB, env-tunable) so a runaway agent cannot exhaust your storage — it clips that trace, never your other traces.
- **Tamper-evident audit ledger** — every recorded event is hash-chained per tenant and batch-anchored to a public transparency log. `tlane verify` re-checks the chain **offline**, from the export alone, with no call back to us. That is the part you can hand to an auditor.
- **Inline heuristic guardrails** — cost, schema, and prompt-injection rails run in-request at the gateway (ML ensemble on the roadmap). Detection is **observe-first** by default: a rail records and flags rather than blocking, because a false-positive block breaks a legitimate run.
- **Cross-language ledger conformance** — the audit verifier is implemented three times, in Rust, Python and TypeScript, and all three are held to **one shared corpus of 8 conformance vectors** that includes deliberately-forged and boundary-numeric cases. **10 Rust + 14 Python + 19 TypeScript** conformance tests run in CI, plus a round-trip job asserting the three implementations agree. That is the suite behind "a third party can verify offline" — you can run it in this clone.
  Note the honest scope: `evals/` here carries the 20 conformance evals; some internal suites target private ADRs and infrastructure and are not part of this repo, so the `test` script says so rather than pretending to pass.
- **Time-travel trace viewer** — step through any recorded agent trace span-by-span with `tlane replay` (read-only). Cross-model re-execution is on the roadmap.

- **MCP tool-definition pinning and lethal-trifecta detection** — shipped, and **free on
every tier including OSS self-host**. Both run as guardrail rails in-request at the
gateway: pinning compares a live tool definition against the hash you approved and flags
divergence; the trifecta rail flags the untrusted-input + private-data + exfiltration-path
combination. Observe-first, like every other rail.

**On the roadmap, not shipped** — named here because they appear elsewhere in our docs
and we would rather you learn it from us than from the source. These live in
`crates/gateway/src/predictive/`, a separate layer from the rails above, and **none of them
fires on LLM traffic today** — for two different reasons:

- **Browser stuck-loop prediction** and **A2UI catalog conformance** gate on payload fields
  (`mcp_server_name`, `tool_name`, `protocol`) that a `/v1/chat/completions` request does
  not carry, so they never reach their scoring path.
- The **distilled SLM judge** runs on every request but is a **stub**: no trained model
  ships, so it returns a constant score and can never flag anything.

See [`apps/docs/predictive-guardrails.mdx`](apps/docs/predictive-guardrails.mdx) for
per-rail status.

## Quick start

**Hosted** (zero infra):

```bash
# 1. Sign up at https://app.tracelane.dev → Settings → API Keys → Create
export TRACELANE_API_KEY=tlane_...
export TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev
```

**Self-host** (Docker Compose):

```bash
git clone https://github.com/tracelane/tracelane
cd tracelane
cp infra/self-host/.env.example infra/self-host/.env

# Edit infra/self-host/.env and set BOTH:
#   TRACELANE_MASTER_KEY  — your gateway key:  openssl rand -base64 32
#   a provider key        — e.g. ANTHROPIC_API_KEY or OPENAI_API_KEY.
#   Without a provider key the gateway starts fine and every request 401s.

docker compose -f infra/self-host/docker-compose.yml up -d

# Load the file you just edited INTO YOUR SHELL. `export FOO="$BAR"` cannot work
# here — BAR was set in a file, so it is empty in the shell and the gateway
# answers 401 on your very first request.
set -a; source infra/self-host/.env; set +a
export TRACELANE_GATEWAY_URL=http://localhost:8080
export TRACELANE_API_KEY="$TRACELANE_MASTER_KEY"
```

Add `--build` to compile the gateway and ingest from source instead of pulling the
published images. **That is a full Rust release build of the workspace and takes
roughly 25 minutes on 8 cores** — the images are the fast path, and `--build` is for
when you are changing the code.

Self-host runs headless: the compose file brings up ClickHouse, NATS, the gateway
(`:8080`) and ingest. **There is no dashboard container** — the web UI is hosted-only
today. Authenticate with the `TRACELANE_MASTER_KEY` from your `.env`; per-key minting
via `POST /v1/keys` needs a Postgres control plane, which self-host does not run.

**The tamper-evident audit ledger DOES run in self-host, with one limit worth knowing
before you rely on it.** Events are hashed into the chain and persisted to ClickHouse
`audit_log` — measured on a clean stack, four chat requests produce eight linked rows
with zero chain breaks. **What self-host does not have is chain resumption across a
gateway restart.** The head is recovered from the Postgres control plane, which
self-host does not run, so on restart the sequence begins again at genesis and you get
duplicate `seq` values that an offline verifier cannot reconstruct across the boundary.

In practice: the ledger is verifiable **within a gateway lifetime**, and a restart
starts a new segment. If you need one continuous, offline-verifiable chain across
restarts today, that is Tracelane Cloud. We would rather state the boundary than let
you find it in a verifier's output.

*(`infra/dev/docker-compose.yml` is the contributor data-plane — ClickHouse, NATS,
Postgres, Grafana on `:3001` — and deliberately starts no gateway. Use it with
`cargo run -p gateway` when hacking on the gateway itself.)*

Then instrument your agent with the SDK — explicit `init()` + per-client
wrapping (nothing is patched on import). `endpoint` is
`https://gateway.tracelane.dev` on Tracelane Cloud (the key needs the `ingest`
scope) or the receiver you run when self-hosting:

```python
from tracelane import init, instrument_anthropic

init(endpoint="https://gateway.tracelane.dev", api_key="tlane_...")

from anthropic import Anthropic

client = Anthropic()
instrument_anthropic(client)  # now messages.create() emits spans
```

```typescript
import { init, instrumentOpenAI } from "@tracelanedev/sdk";

init({
  endpoint: "https://gateway.tracelane.dev",
  apiKey: process.env.TRACELANE_API_KEY!,
});

import OpenAI from "openai";
const client = new OpenAI();
instrumentOpenAI(client);  // now chat.completions are traced
```

## Architecture

```
Agent / SDK
    │
    ▼
┌─────────────────────────────────────┐
│  Rust Gateway (Axum + tokio)        │
│  - BYOK routing to 150+ providers    │
│  - Inline heuristic guardrails      │
│  - OTLP span emit                   │
└────────────────┬────────────────────┘
                 │ NATS JetStream
                 ▼
┌─────────────────────────────────────┐
│  Rust Ingest Workers                │
│  - High-throughput batch writes     │
│  - ClickHouse batch writes          │
│  - Full-fidelity capture (default)  │
└────────────────┬────────────────────┘
                 │
     ┌───────────┴───────────┐
     ▼                       ▼
ClickHouse              Cloudflare
(hot tier)              R2 (cold, roadmap)
```

## Repository structure

| Path | Language | Purpose |
|------|----------|---------|
| `crates/gateway/` | Rust | BYOK LLM proxy, inline guardrails, audit chain |
| `crates/ingest/` | Rust | OTLP receiver, NATS consumer, ClickHouse writer |
| `crates/shared/` | Rust | Shared types (ChatRequest, TracelaneSpan, TenantId) |
| `crates/tracelane-audit-cli/` | Rust | `tracelane-audit` — standalone offline ledger verifier |
| `crates/policy/` | Rust | PII redactors (wired into the audit + guardrail paths) + a Cedar policy-engine scaffold that is **not** wired in V1 |
| `apps/web/` | TypeScript | Next.js 15 dashboard |
| `apps/mcp/` | TypeScript | Tenant-scoped MCP server |
| `packages/sdk-typescript/` | TypeScript | Agent instrumentation SDK |
| `packages/sdk-python/` | Python | Agent instrumentation SDK |
| `packages/cli/` | TypeScript | `tlane` CLI |
| `evals/` | TypeScript | 20 conformance evals — 10 fault-tolerance, 7 gateway-correctness, and one each for ingest-schema, PII-redaction and prompt-injection |
| `ml/` | Python | Trajectory Guard / SLM judge — training + export pipeline; no trained weights ship yet |
| `spec/openagenttrace/` | Markdown | OpenAgentTrace v0.1 spec |
| `spec/aft-1/` | Markdown | Agent Failure Taxonomy — 13 published failure modes |
| `infra/dev/` | YAML/SQL | Docker Compose + ClickHouse schema |

## Development

```bash
# Prerequisites: Rust 1.95 (pinned in rust-toolchain.toml; MSRV 1.88), Node.js 22+, pnpm 9+

pnpm install
cargo build --workspace

# Start local services
docker compose -f infra/dev/docker-compose.yml up -d

# Run gateway
cargo run -p gateway

# Run ingest
cargo run -p ingest

# Run eval suite (reports; no required status check blocks a merge on it)
pnpm eval:run --suite=all
```

## Migrating from LiteLLM

Tracelane's gateway is memory-safe Rust with no admin configuration endpoints, no
`eval`, and no import-by-string of untrusted config. If you are moving an existing
LiteLLM deployment, the importer reads your config directly.

One command reads your existing config and emits a Tracelane gateway config:

```bash
npx @tracelanedev/cli import-litellm --config litellm_config.yaml
```

Then point your agents at `TRACELANE_GATEWAY_URL`. The gateway is OpenAI-**path**
compatible (`/v1/chat/completions`), and the request body follows the Anthropic tool
schema (`{name, description, input_schema}`). Both tool shapes are accepted: an OpenAI-shaped
`tools: [{type: "function", function: {...}}]` array and the Anthropic shape are
normalised to one internal representation, so no request rewriting is required.

Full guide: [docs.tracelane.dev/migrations/from-litellm](https://docs.tracelane.dev/migrations/from-litellm)

### Verifying Tracelane releases

```bash
# Use a current cosign release to verify.
cosign verify-blob \
  --bundle gateway-x86_64-unknown-linux-gnu.cosign.bundle \
  --certificate-identity-regexp="https://github.com/tracelane/tracelane/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  gateway-x86_64-unknown-linux-gnu
```

All binaries are Cosign-signed (keyless OIDC) with build provenance attested via
`actions/attest-build-provenance`, and a CycloneDX SBOM is published with each release.
We use Grype + Syft + OSV-Scanner (not Trivy) in CI.

Honest note on this repository: it is a **one-way export** of a private monorepo, not
the tree development happens in. Every commit here is a squashed publication, so `main`
carries no branch protection and no review history you can inspect — the merge gating,
the full test suite and the guard selftests run upstream before anything is exported.
Judge the code and the releases, not the commit graph.

Honest note on SLSA: the repository runs `slsa-framework/slsa-github-generator`, but its
`final` job is currently failing even on successful releases, so **we do not claim a
verified SLSA Level 3 attestation**. The provenance you can actually verify today is the
`attest-build-provenance` one, alongside the Cosign bundle above.

## Migrating from Helicone

One command rewrites your Helicone base URL and auth headers to Tracelane (config +
environment only — no trace re-import needed):

```bash
npx @tracelanedev/cli migrate helicone --apply
```

Full guide: [docs.tracelane.dev/migrations/from-helicone](https://docs.tracelane.dev/migrations/from-helicone)

## Pricing

OSS self-host is **$0 forever** under Apache 2.0, with no commercial restriction. What it runs is the headless stack — ClickHouse, NATS, gateway and ingest; there is no dashboard container, and the web UI is hosted-only today (see [Self-host](#quick-start) above). Hosted tiers (free / $59 Builder / $249 Team / $899 Business / $2,999+ Enterprise + $999/mo Audit add-on) with capped overage and bundled seats are documented at **[tracelane.dev/pricing](https://tracelane.dev/pricing)**, and the same ladder is published at [docs.tracelane.dev/pricing](https://docs.tracelane.dev/pricing).

## Community

- **Discussions:** [github.com/tracelane/tracelane/discussions](https://github.com/tracelane/tracelane/discussions) — ask questions, share traces, get help
- **Issues:** [github.com/tracelane/tracelane/issues](https://github.com/tracelane/tracelane/issues)
- **Security:** `security@tracelane.dev` (90-day responsible disclosure)

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=tracelane/tracelane&type=Date)](https://star-history.com/#tracelane/tracelane&Date)

## License

Apache 2.0. See [LICENSE](./LICENSE) and [LICENSE-PLEDGE.md](./LICENSE-PLEDGE.md).

Apache 2.0 grants are perpetual and irrevocable, so every release already published
under Apache 2.0 stays Apache 2.0 — neither we nor any future owner can take that back.
[LICENSE-PLEDGE.md](./LICENSE-PLEDGE.md) sets out what we commit to beyond that, and is
explicit about where the commitment is enforceable and where it is only a promise.


