# Tracelane

**Predictive reliability platform for AI agents.**

[![CI](https://github.com/tracelane/tracelane/actions/workflows/ci.yml/badge.svg)](https://github.com/tracelane/tracelane/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OTel GenAI semconv](https://img.shields.io/badge/OTel-GenAI%20semconv-brightgreen)](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
[![Cosign verified](https://img.shields.io/badge/releases-cosign%20verified-blueviolet)](SECURITY.md#verifying-release-artifacts)
[![SLSA Level 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Discord](https://img.shields.io/discord/tracelane?label=Discord&logo=discord&logoColor=white)](https://discord.gg/tracelane)

**[Get started free →](https://app.tracelane.dev/signup)** · [Docs](https://docs.tracelane.dev) · [Discord](https://discord.gg/tracelane)

---

## What it does

Tracelane sits between your AI agents and your LLM providers. You get:

- **BYOK proxy** — point agents at `https://gateway.tracelane.dev`, pass your own API key. 0% markup.
- **Full-fidelity traces** — every LLM call, tool invocation, agent step, and retry captured as OTel spans with OpenInference attributes.
- **Predictive guardrails** — MCP rug-pull detection, lethal-trifecta taint tracking, browser stuck-loop prediction, A2UI catalog conformance — inline at the gateway.
- **CI-gate evals** — 50 pain-point assertions run as a merge gate; a regression blocks the PR.
- **Time-travel trace viewer** — step through any recorded agent trace span-by-span with `tlane replay` (read-only). Cross-model re-execution is on the roadmap.

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
docker compose -f infra/dev/docker-compose.yml up -d

export TRACELANE_GATEWAY_URL=http://localhost:8080
export TRACELANE_API_KEY=tlane_...   # create via the dashboard at :3000
```

Then instrument your agent with the SDK — explicit `init()` + per-client
wrapping (nothing is patched on import):

```python
from tracelane import init, instrument_anthropic

init(endpoint="http://localhost:4318", api_key="tlane_...")

from anthropic import Anthropic
client = Anthropic()
instrument_anthropic(client)  # now messages.create() emits spans
```

```typescript
import { init, instrumentOpenAI } from "@tracelanedev/sdk";

init({ endpoint: "http://localhost:4318", apiKey: process.env.TRACELANE_API_KEY! });

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
│  - BYOK routing to 30+ providers    │
│  - Predictive layer inline          │
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
(90-day hot)            R2 (cold)
```

## Repository structure

| Path | Language | Purpose |
|------|----------|---------|
| `crates/gateway/` | Rust | BYOK LLM proxy, predictive layer |
| `crates/ingest/` | Rust | OTLP receiver, NATS consumer, ClickHouse writer |
| `crates/shared/` | Rust | Shared types (ChatRequest, TracelaneSpan, TenantId) |
| `crates/mcp-rs/` | Rust | Native MCP protocol implementation |
| `crates/policy/` | Rust | Cedar policy engine integration |
| `apps/web/` | TypeScript | Next.js 15 dashboard |
| `apps/mcp/` | TypeScript | Tenant-scoped MCP server |
| `packages/sdk-typescript/` | TypeScript | Agent instrumentation SDK |
| `packages/sdk-python/` | Python | Agent instrumentation SDK |
| `packages/cli/` | TypeScript | `tlane` CLI |
| `evals/` | TypeScript | 50 pain-point assertions (merge gate) |
| `ml/` | Python | Trajectory Guard, SLM judge |
| `spec/openagenttrace/` | Markdown | OpenAgentTrace v0.1 spec |
| `spec/aft-1/` | Markdown | Agent Failure Taxonomy 22 failure modes |
| `decisions/` | Markdown | ADR-001 through ADR-006+ |
| `infra/dev/` | YAML/SQL | Docker Compose + ClickHouse schema |

## Development

```bash
# Prerequisites: Rust 1.87+, Node.js 22+, pnpm 9+

pnpm install
cargo build --workspace

# Start local services
docker compose -f infra/dev/docker-compose.yml up -d

# Run gateway
cargo run -p gateway

# Run ingest
cargo run -p ingest

# Run eval suite (merge gate)
pnpm eval:run --suite=all
```

## Migrating from LiteLLM

Two critical CVEs in 30 days (CVE-2026-33634 CVSS 9.4, CVE-2026-42208 CVSS 9.3)
made LiteLLM the most-discussed migration target in enterprise AI in 2026.

Migrate in under 5 minutes:

```bash
npx @tracelanedev/cli import-litellm litellm_config.yaml
```

Then point your agents at `TRACELANE_GATEWAY_URL` — the gateway is OpenAI-API-compatible.

Full guide: [docs/migrations/from-litellm.md](docs/migrations/from-litellm.md)

### Verifying Tracelane releases

```bash
cosign verify-blob \
  --bundle gateway-x86_64-unknown-linux-gnu.cosign.bundle \
  --certificate-identity-regexp="https://github.com/tracelane/tracelane/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  gateway-x86_64-unknown-linux-gnu
```

All binaries are Cosign-signed (keyless OIDC), SLSA Level 3 provenance attached,
CycloneDX SBOM included. We use Grype (not Trivy) in CI — see [ADR-007](decisions/ADR-007-grype-not-trivy.md).

## Migrating from Helicone

Helicone was acquired by Mintlify (March 2026) and is in maintenance mode. One command rewrites your
Helicone base URL and auth headers to Tracelane (config + environment only — no trace re-import needed):

```bash
npx @tracelanedev/cli migrate helicone --apply
```

Full guide: [docs/migrations/from-helicone.md](docs/migrations/from-helicone.md)

## Pricing

OSS self-host is **$0 forever** under Apache 2.0 — full stack, no commercial restriction. Hosted tiers (free / $59 Builder / $249 Team / $899 Business / $2,999+ Enterprise + $999/mo Audit add-on) with capped overage and bundled seats are documented at **[tracelane.dev/pricing](https://tracelane.dev/pricing)** (single source).

## Community

- **Discord:** [discord.gg/tracelane](https://discord.gg/tracelane) — ask questions, share traces, get help
- **Issues:** [github.com/tracelane/tracelane/issues](https://github.com/tracelane/tracelane/issues)
- **Security:** `security@tracelane.dev` (90-day responsible disclosure)

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=tracelane/tracelane&type=Date)](https://star-history.com/#tracelane/tracelane&Date)

## License

Apache 2.0. See [LICENSE](./LICENSE) and [LICENSE-PLEDGE.md](./LICENSE-PLEDGE.md).

The license will never be changed. See the pledge for the BSL trigger clause
that makes this legally binding.


