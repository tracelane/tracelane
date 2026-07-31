# Changelog

All notable changes to Tracelane are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Tracelane follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> This is the public release changelog. It records user-facing features and fixes
> at a feature level. Performance numbers are stated qualitatively until the
> Reliability Benchmark v1.0 publishes measured results on production-equivalent
> hardware. Items marked **(roadmap)** are not yet shipped.

## [Unreleased]

## [0.2.2] - 2026-07-31

First release to ship **signed** artifacts. v0.2.1 published packages to npm and
PyPI but never produced a GitHub Release, Cosign signatures, a release SBOM, or
SLSA provenance — the release job failed before reaching them. That is closed here.

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

- All published packages are unified at 0.2.2 so that the version of every
  artifact matches the release tag it came from. The SDKs and the three verifiers
  have no source changes since 0.2.1; they are re-cut so their artifacts come
  from the signed-tag path.


### Added

- **Rust gateway** — OpenAI-, Anthropic-, and Google-shaped request proxying across
  30+ providers (6 native adapters plus any OpenAI-compatible endpoint), with
  provider failover, retry with jittered backoff, and per-`(provider, region)`
  circuit breakers. Low, bounded overhead on the hot path.
- **BYOK key custody** — provider keys are envelope-encrypted at rest (`aws-lc-rs`
  AEAD), with AAD bound to `(tenant_id, provider_id)`. Keys never appear in logs,
  spans, or error bodies.
- **Full-fidelity observability** — OTel GenAI + OpenInference semantic conventions
  over ClickHouse, with a WebGL/transcript-spine trace viewer and Cmd+K navigation
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
