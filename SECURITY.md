# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` branch | ✅ Active |
| Tagged releases | ✅ Last 2 minor versions |
| Older releases | ❌ No security patches |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **security@tracelane.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact
- Any proof-of-concept (privately, please)

We will acknowledge receipt within **72 hours** and provide a remediation
timeline within 7 days; we target a **30-day patch** for critical
vulnerabilities. We follow responsible disclosure: 90-day embargo before public
disclosure, coordinated with reporter.

## Security guarantees

### What Tracelane guarantees

- **BYOK only:** Provider API keys are envelope-encrypted at rest with
  **AES-256-GCM via `ring`**. Each ciphertext is bound to its
  `(tenant_id, provider_id)` via AAD — a row swap across tenants
  fails GCM authentication. Master key (32 bytes) is loaded from
  `TRACELANE_BYOK_MASTER_KEY` at startup; production deployments
  source the env var from a KMS (AWS KMS / GCP KMS / Vault) at
  process launch. Keys never appear in logs, spans, or errors — the
  tracing redaction filter scrubs OpenAI `sk-`, Anthropic `sk-ant-`,
  Google `AIza`, Stripe / Polar `sk_live_/whsec_/rk_`, AWS `AKIA`,
  bare `Bearer`, and JWT-shaped tokens.
- **Tenant isolation:** Every ClickHouse query includes
  `WHERE tenant_id = ?`. `tenant_id` is extracted from a validated
  JWT claim or a verified SPIFFE X.509-SVID only — never from the
  request body. The `tracelane_shared::TenantId` type can only be
  constructed via `from_jwt_claim` or `from_spiffe_svid`, making
  body-supplied values a compile-time impossibility.
- **JWT validation:** Algorithm allowlist
  `[RS256, RS384, RS512, ES256, EdDSA]`. HMAC family hard-denied
  (closes the alg-confusion attack class). `WORKOS_AUDIENCE`
  mandatory in release builds.
- **Webhook integrity:** Polar.sh (payments) and WorkOS (auth)
  webhook handlers verify HMAC signatures in constant time, reject
  events older than 5 minutes, and dedupe on `(source, event_id)`
  via Postgres before any side effect runs. Replay cannot re-fire
  `subscription.deleted` to downgrade a paying tenant.
- **SSRF:** All outbound HTTP from gateway providers passes through
  `validate_url`. Blocked ranges: RFC 1918, 100.64/10, 169.254/16
  (AWS/GCP IMDS), 168.63.129.16 (Azure IMDS), 127/8, ::1, ::,
  fc00::/7, 240/4, 2001:db8::/32, and **IPv4-mapped IPv6**
  (recurses through `to_ipv4_mapped`). HTTP redirects are
  **disabled** on the SSRF-hardened client (mythos round-3 B-1) —
  per-hop sync validation could not catch domain-resolves-to-
  private-IP TOCTOU attacks, so every caller now talks to a fixed
  endpoint. Future callers wanting redirects must re-validate each
  `Location:` via the async `validate_url`.
- **mTLS for ingest:** SPIFFE/SPIRE-issued X.509-SVIDs with 1-hour
  rotation, hot-reloaded via the SPIRE Workload API into an
  `arc-swap`-installed trust bundle (per-connection cache; new
  handshakes pick up rotated bundles, in-flight requests complete
  on old bundles). TLS 1.3 minimum; client auth mandatory; rustls
  `ClientCertVerifier` validates the chain against the SPIRE bundle.
  Application-layer SVID checks (BasicConstraints::cA = false,
  KeyUsage::digital_signature, ASCII-case-insensitive trust domain,
  path shape `/tenant/<uuid>/ingest-worker`) live in
  `crates/ingest/src/auth.rs`.
- **Tamper-evident audit ledger** (`$999/mo` SKU): per-tenant SHA-256
  hash chain. Row hash uses length-prefixed, domain-separated framing
  (`tracelane-audit-row-v2\0`) — field-boundary attacks via
  attacker-controlled `actor` cannot collide rows. Merkle tree per
  RFC 6962 §2.1 (leaf prefix `0x00`, node prefix `0x01`, raw bytes;
  lone-odd-leaf promoted, not duplicated — closes second-preimage).
  Every 100 events the Merkle root is signed with a per-tenant
  Ed25519 key (envelope-encrypted via BYOK; Enterprise tier) or the
  global key (lower tiers), and submitted to Sigstore Rekor v2 as a
  `hashedrekord`. Chain state persists across restarts via the
  `audit_chain_state` Postgres table with monotonic UPSERT
  semantics.
- **Prompt injection awareness:** User-supplied span content is
  wrapped in `<UNTRUSTED_USER_DATA>` sentinel before any agent reads
  it. PII redaction (`crates/policy/src/pii.rs`) runs over audit
  payloads before they enter the chain — secrets that leak past a
  caller cannot reach ClickHouse or Rekor anchor batches.
- **Supply chain:** Trusted Publishing OIDC only (no long-lived
  tokens). Sigstore Cosign keyless signatures on all releases.
  CycloneDX SBOM attached. SLSA Build Level 3 provenance on all
  artifacts. `.pth` file scanner in CI.
- **No admin endpoints:** Tracelane has no `/config/update`-style
  endpoints. No `eval` or import-by-string of untrusted
  configuration.
- **Dependency hygiene:** `cargo audit` and `pnpm audit` run on
  every PR. No new dependencies from publishers under 6 months
  tenure or under 100 stars without security-reviewer approval.

### Known gaps vs the published guarantees

These are work-in-progress as of 2026-05-23 and are explicitly NOT
yet guaranteed:

- **Customer-side audit verifier**: `packages/verifier-rust/src/lib.rs`
  currently only checks that Rekor returns HTTP 200; it does not yet
  validate the Ed25519 signature or the Rekor inclusion proof. The
  server-side primitives are correct (see "Tamper-evident audit
  ledger" above), but the end-to-end "tamper-evident with
  customer-runnable cryptographic verification" claim requires the
  verifier rewrite (tracked as R1 H1/H2 — pending).
- **API-key storage**: keys are SHA-256-hashed without salt or KDF.
  Argon2id migration is planned. A DB dump exposes hashes that are
  trivially confirmable against candidate strings.
- **JWKS fetch**: uses bare `reqwest::get` with no TLS pinning or
  host allowlist on `WORKOS_JWKS_URL`. Planned: rustls client with
  TLS 1.3 and host suffix allowlist.
- **eIDAS qualified timestamps**: audit-ledger anchors use the
  gateway host's `Utc::now()`. A move to a qualified TSA (SwissSign,
  Sectigo, GlobalSign QTSP) is in scope for the Audit-SKU GA.

Each will be removed from this list as the corresponding PR lands.

### LiteLLM-specific mitigations

Given the March 2026 LiteLLM incidents (RCE via `/config/update`, JWT bypass,
SQLi+SSTI+command injection chain), Tracelane explicitly:

- Exposes no admin configuration endpoints
- Uses Cedar (Apache 2.0) for policy enforcement, not string-eval
- Requires 2 maintainer approvals on release tags
- Scans every release for new `.pth` files (ML model backdoor vector)
- Signs all release tags with Sigstore

## Cryptography

- **TLS:** `rustls` 0.23 with the **ring** crypto provider — never
  `openssl`. (The `aws-lc-rs` crate is linked transitively because
  it's rustls's default feature, but Tracelane code paths use `ring`
  exclusively.)
- **Symmetric encryption (BYOK envelope):** AES-256-GCM via `ring`.
  Wire format prepends a version byte (`0x02` = v2) and binds the
  ciphertext to a caller-supplied AAD that includes the `tenant_id`
  and the asset kind (`provider-key:<tenant>:<provider>` or
  `audit-key:<tenant>`). v1 blobs (pre-Phase-5, empty AAD) decrypt
  with a `warn` log so operators can plan the re-encryption migration.
- **Asymmetric (audit-ledger signing):** Ed25519 via `ring`.
  Per-tenant keypairs (Enterprise tier, gated by
  `entitlements::F_AUDIT_KEYPAIR`) generated and stored
  envelope-encrypted in `tenant_audit_keys` Postgres rows; lower
  tiers fall back to a process-global key from
  `TRACELANE_REKOR_SIGNING_KEY`. Private-key PKCS#8 bytes are
  wrapped in `secrecy::SecretBox` and zeroized on drop.
- **Hashing:** SHA-256 (audit row hash, RFC 6962 Merkle tree,
  MCP tool-schema fingerprinting).
- **Key derivation:** HKDF-SHA256 where applicable.

## Known limitations

- Free-tier rate limits (60 RPM) reduce abuse surface but do not eliminate it
- SLM judge inference latency (<50ms p99) means there is a brief window between
  request arrival and predictive decision — this is inherent to inline ML
- Trajectory Guard F1 0.88–0.94 means ~6–12% of anomalies may not be detected;
  rule-based Tier 1 guards (hash watcher, taint tracker) have 100% coverage for
  their defined threat models

## Acknowledgments

We credit the following researchers whose public work informs Tracelane's
security design:
- Invariant Labs (MCP rug-pull attack research)
- Pipelock/Straiker (behavioral fingerprinting)
- CyberArk (Poison Everywhere injection surface)
- Microsoft AgentRx and Agent Governance Toolkit
- OWASP Agentic Top-10 working group

## Verifying release artifacts

All Tracelane release binaries are signed with [Sigstore Cosign](https://sigstore.dev)
keyless OIDC. Verify a downloaded binary:

```bash
cosign verify-blob \
  --bundle <binary>.cosign.bundle \
  --certificate-identity-regexp="https://github.com/tracelane/tracelane/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  <binary>
```

The Docker image is also signed. Verify:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/tracelane/tracelane/.*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/tracelane/gateway:latest
```

SBOM (CycloneDX JSON) is attached to every GitHub release as `sbom.cyclonedx.json`.
SLSA Build Level 3 provenance is attached via GitHub Attestations.

### Why we use Grype instead of Trivy

CVE-2026-33634 compromised LiteLLM v1.82.7/1.82.8 via a poisoned Trivy GitHub Action
(`aquasecurity/trivy-action`). The compromised action was distributed through GitHub's
action marketplace. We use Grype (Anchore) with a pinned release binary instead, and
all our CI actions are SHA-pinned to a specific commit rather than a floating tag.
This choice is documented in [decisions/ADR-007-grype-not-trivy.md](decisions/ADR-007-grype-not-trivy.md).
