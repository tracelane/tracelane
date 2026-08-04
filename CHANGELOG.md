# Changelog

All notable changes to Tracelane are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Tracelane follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> This is the public release changelog. It records user-facing features and fixes
> at a feature level. Performance numbers are stated qualitatively until the
> Reliability Benchmark v1.0 publishes measured results on production-equivalent
> hardware. Items marked **(roadmap)** are not yet shipped.

## [Unreleased]

### Changed — BREAKING for self-host

**Guardrail rails are now split into a free set and a paid set, and a gateway
with no control plane resolves to the FREE set instead of granting everything.**

Free on every deployment — OSS self-host and every hosted tier, including free:

| rail | what it does |
|---|---|
| `R1_cost` | request cost ceiling |
| `R3_schema` | tool-call schema validation |
| `R3_pinning` | **MCP tool-definition drift / rug-pull detection** |
| `R4_trifecta` | **lethal-trifecta taint tracking** |
| `R8_injection` | prompt-injection patterns |

Gated behind a control-plane entitlement (`f_guardrail_*`):
`R2_secrets_pii` · `R5_format` · `R6_sysprompt_leak` · `R7_topic_competitor`.

The dividing line: **agent-safety and basic correctness are free; product,
quality and data-governance rails are paid.** `R3_pinning` and `R4_trifecta`
moved from paid to free in this release — a flagship agent-safety capability
that a free tier never sees is not a capability anyone can evaluate, and
`R8_injection` was already free, so gating the same attack family on the other
side of the paywall was an incoherent line.

**UPGRADE NOTE — self-host deployments lose four rails.** Before this release, a
gateway started without a Postgres control plane granted *every* rail, so an OSS
self-host ran the full set — more guardrails than a paying Builder-tier customer.
That was a bug (an entitlement default that granted instead of denying), not a
policy. After upgrading, a self-host install without a control plane runs the
five free rails; `R2_secrets_pii`, `R5_format`, `R6_sysprompt_leak` and
`R7_topic_competitor` stop running unless entitlements grant them. If you relied
on any of those four, see below.

**Open-core honesty — can a self-hoster still enable the paid four?** Yes, in one
of the two self-host configurations, and we would rather say so than let you
discover it:

- **Single-tenant self-host** (`TRACELANE_SELF_HOST=1`, the `infra/self-host`
  compose path) **cannot**: that mode refuses to start if a control-plane
  Postgres is present at all, so it always resolves to the free five.
- **Multi-tenant self-host** (leave `TRACELANE_SELF_HOST` unset and run your own
  Postgres) **can**: the gate reads `plan_entitlements` / `workspace_entitlements`
  from *your* database. There is no license key, no signature check and no
  phone-home anywhere in the entitlement path — a single `UPDATE
  plan_entitlements SET f_guardrail_r2 = true …` enables all four.

So the gate binds **hosted** customers commercially, not self-hosters
technically. Making it bind self-hosters would need a license boundary this
project does not have and, per `LICENSE-PLEDGE.md`, will not add. Everything
here is Apache 2.0; there is no separate enterprise tree.

## [0.2.3] - 2026-08-01

**First release to ship signed artifacts.** 0.2.1 and 0.2.2 both published
packages to npm and PyPI while producing no GitHub Release, no Cosign
signatures, no release SBOM and no SLSA provenance. 0.2.3 is 0.2.2's payload
plus the two defects that stopped it: a release action pinned to a commit SHA
that does not exist upstream, and a container SBOM step that tried to write
release assets from a read-only job. The four cross-compiled binaries are now
published under per-target names — previously all four shared one filename, so
a flat release-asset namespace would have kept only one.

Every published package moves to 0.2.3.

### Fixed

- **`tlane init` writes atomically.** The config write checked `existsSync` and
  then wrote, a race in which anything created in between — including a symlink
  to a path you did not intend to write — was overwritten *without* `--force`. It
  is now a single exclusive-create syscall, so the refusal is enforced by the
  write itself. `--force` still overwrites.
- **`tlane prompt diff` pins its temporary filenames.** The prompt name and the
  two environment flags were interpolated into a temp-file path, so a `../` could
  escape the temp directory. Both sides are now pinned inside the freshly created
  directory.

### Security

- Webhook log fields are stripped of CR/LF and control characters before logging,
  so a provider-relayed, customer-controlled value cannot forge a log entry.

### Changed

- All published packages are unified at 0.2.3 so that the version of every
  artifact matches the release tag it came from. The SDKs and the three verifiers
  have no source changes since 0.2.1; they are re-cut so their artifacts come
  from the signed-tag path.

## [0.2.2] - 2026-08-01

Published to npm and PyPI; produced no signed artifacts — no GitHub Release, no
Cosign signatures, no SBOM, no SLSA provenance — for the reasons fixed in 0.2.3.
The tag was signed and verified; the failure was downstream of the signature
gate. Prefer 0.2.3: it carries the same code with a verifiable release.


### Added

- **Rust gateway** — OpenAI-, Anthropic-, and Google-shaped request proxying across
  30+ providers (7 native adapters plus any OpenAI-compatible endpoint), with
  provider failover, retry with jittered backoff, and per-`(provider, region)`
  circuit breakers. Low, bounded overhead on the hot path.
- **BYOK key custody** — provider keys are envelope-encrypted at rest (`aws-lc-rs`
  AEAD), with AAD bound to `(tenant_id, provider_id)`. Keys never appear in logs,
  spans, or error bodies.
- **Full-fidelity observability** — OTel GenAI + OpenInference semantic conventions
  over ClickHouse, with a transcript-spine trace viewer and Cmd+K navigation
  in the Next.js dashboard.
- **Tamper-evident audit ledger** — per-tenant Merkle-batched hash chain with an
  offline, no-account verifier (`@tracelanedev/cli` `tlane verify --offline`) for EU AI
  Act Article 12 record-keeping. Sigstore Rekor anchoring is **(roadmap)**.
- **Inline guardrails** — heuristic pre-flight policy enforcement at the gateway
  (cost, secret/PII, tool-safety, lethal-trifecta taint, format, system-prompt-leak,
  topic). A multi-model ML ensemble and async judge are **(roadmap)**.
- **Predictive signatures** — live failure-signature detection surfaced on the
  Signatures page; additional predictors ship progressively behind entitlement flags.
- **MCP server** — read-only, tenant-scoped, OAuth 2.1 (Stdio + Streamable HTTP).
- **SDKs + CLI** — Python and TypeScript instrumentation SDKs (40+ framework
  adapters, never capture keys or content), and the `tlane` CLI (`init`, `verify`,
  `import`, `migrate`, `replay`, `eval`).
- **Migration tooling** — `tlane migrate helicone` rewrites config + environment
  (base URL + auth headers) as a reviewable diff; `tlane import langsmith` reads
  existing projects, traces, and prompt versions. Historical trace-data import is
  **(roadmap)**.
- **Supply-chain trust** — Cosign keyless signatures, CycloneDX SBOMs, SLSA Build
  Level 3 provenance, OSV-Scanner + Grype + Syft scanning, and OIDC Trusted
  Publishing on every release artifact.

### Changed

- Marketing and product copy use qualitative performance language until measured
  benchmark results are published (Reliability Benchmark v1.0).

### Security

- Tenant isolation is structural — every analytics query is scoped by a
  JWT/SVID-derived `tenant_id`, never a request body.
- SSRF defense on every outbound request; TLS 1.3 minimum end-to-end; mTLS for ingest.

[Unreleased]: https://github.com/tracelane/tracelane/commits/main
